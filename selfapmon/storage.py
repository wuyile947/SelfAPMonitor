"""本地 SQLite 存储队列 + 日志轮转 + CSV 导出.

表结构:
  devices    设备上下线历史
  events     事件日志 (上线/下线/告警/管控动作)
  dns_log    DNS 查询 (明文域名; 加密DNS/ECH 仅标记不解析)
  flows      会话/流记录 (五元组+分类+TLS明文元数据)

写入模型: 后台单写线程 + 无界队列 (主线程永不阻塞)
轮转模型: 启动时清理过期记录 + 周期检查 db 体积, 超限删最旧明细 + VACUUM
"""
import csv
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime, timedelta

from . import app_root

DB_DIR = os.path.join(app_root(), "data")
DB_PATH = os.path.join(DB_DIR, "selfapmon.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, mac TEXT, ip TEXT, event TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, kind TEXT, mac TEXT, ip TEXT, msg TEXT
);
CREATE TABLE IF NOT EXISTS dns_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, mac TEXT, ip TEXT, qname TEXT, qtype TEXT,
  encrypted INTEGER, ech INTEGER, answers TEXT
);
CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_ts REAL, last_ts REAL, mac TEXT, ip TEXT, proto INTEGER,
  sport INTEGER, dport INTEGER, raddr TEXT, category TEXT, detail TEXT,
  bytes_up INTEGER, bytes_down INTEGER,
  sni TEXT, alpn TEXT, ja3 TEXT, ech INTEGER, esni INTEGER, tls_version TEXT, qname TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ts ON devices(ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_log(ts);
CREATE INDEX IF NOT EXISTS idx_dns_mac ON dns_log(mac);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(first_ts);
CREATE INDEX IF NOT EXISTS idx_flows_mac ON flows(mac);
"""


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


class Storage:
    def __init__(self, config):
        self.config = config
        os.makedirs(DB_DIR, exist_ok=True)
        self.db_path = DB_PATH
        self._q = queue.Queue(maxsize=100000)
        self._stop = threading.Event()
        self._conn = None
        self._lock = threading.Lock()
        self._init_db()
        self._writer = threading.Thread(target=self._write_loop, daemon=True, name="DBWriter")
        self._writer.start()
        self._rotate_check()

    # ---------- 初始化 ----------
    def _init_db(self):
        try:
            self._create_schema()
        except sqlite3.OperationalError:
            # disk I/O error 等: 多为强杀进程留下的损坏 -wal/-shm 残片,
            # 主库未损坏时隔离残片即可恢复 (残片改名备份, 不删)
            for ext in ("-wal", "-shm"):
                p = self.db_path + ext
                try:
                    if os.path.exists(p):
                        os.rename(p, p + ".broken" + str(int(time.time())))
                except Exception:
                    pass
            self._create_schema()

    def _create_schema(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _conn_open(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    # ---------- 写线程 ----------
    def _write_loop(self):
        while not self._stop.is_set():
            batch = []
            try:
                item = self._q.get(timeout=1.0)
                batch.append(item)
                while len(batch) < 500:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            except Exception:
                continue
            if batch:
                self._write_batch(batch)
                self._maybe_rotate()

    def _write_batch(self, batch):
        try:
            with self._lock:
                conn = self._conn_open()
                for kind, args in batch:
                    if kind == "device":
                        conn.execute("INSERT INTO devices(ts,mac,ip,event) VALUES(?,?,?,?)", args)
                    elif kind == "event":
                        conn.execute("INSERT INTO events(ts,kind,mac,ip,msg) VALUES(?,?,?,?,?)", args)
                    elif kind == "dns":
                        conn.execute(
                            "INSERT INTO dns_log(ts,mac,ip,qname,qtype,encrypted,ech,answers) "
                            "VALUES(?,?,?,?,?,?,?,?)", args)
                    elif kind == "flow":
                        conn.execute(
                            "INSERT INTO flows(first_ts,last_ts,mac,ip,proto,sport,dport,raddr,"
                            "category,detail,bytes_up,bytes_down,sni,alpn,ja3,ech,esni,tls_version,qname) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", args)
                conn.commit()
        except Exception:
            pass

    # ---------- 公开写接口 (线程安全, 入队即返回) ----------
    def log_device(self, mac, ip, event):
        self._try_put(("device", (time.time(), mac, ip, event)))

    def log_event(self, kind, mac, ip, msg):
        self._try_put(("event", (time.time(), kind, mac, ip, msg)))

    def log_dns(self, mac, ip, qname, qtype, encrypted=False, ech_flag=False, answers=None):
        self._try_put(("dns", (time.time(), mac, ip, qname, qtype,
                               1 if encrypted else 0, 1 if ech_flag else 0,
                               ";".join(answers or [])[:512])))

    def log_flow(self, mac, ip, proto, sport, dport, raddr, category, detail,
                 bytes_up, bytes_down, sni="", alpn="", ja3="", ech=False,
                 esni=False, tls_version="", qname="", first_ts=0, last_ts=0):
        self._try_put(("flow", (first_ts, last_ts, mac, ip, proto, sport, dport,
                                raddr, category, detail, bytes_up, bytes_down,
                                sni, alpn, ja3, 1 if ech else 0, 1 if esni else 0,
                                tls_version, qname)))

    def sum_flows_since(self, mac, raddr, since_ts):
        """查询已入库流: 某设备 -> 某远端IP 自 since_ts 起的 (连接数, 总字节).

        供网络净化的流量推断使用 (已结束入库的流不在 sniffer 活动流表里)."""
        try:
            with self._lock:
                conn = self._conn_open()
                row = conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(bytes_up+bytes_down),0) FROM flows "
                    "WHERE mac=? AND raddr=? AND first_ts>=?",
                    (mac, raddr, since_ts)).fetchone()
            return (int(row[0]), int(row[1]))
        except Exception:
            return (0, 0)

    def _try_put(self, item):
        try:
            self._q.put_nowait(item)
        except queue.Full:
            try:
                self._q.get_nowait()
                self._q.put_nowait(item)
            except Exception:
                pass

    # ---------- 轮转/清理 ----------
    def _rotate_check(self):
        self.prune_old(self.config.get("db_retention_days"))

    def _maybe_rotate(self):
        # 每 ~500 批检查一次体积
        if (getattr(self, "_op_count", 0) % 500) == 0:
            self._op_count = getattr(self, "_op_count", 0) + 1
            try:
                size_mb = os.path.getsize(self.db_path) / 1048576
                if size_mb > float(self.config.get("db_max_mb")):
                    self._shrink()
            except Exception:
                pass
        else:
            self._op_count = getattr(self, "_op_count", 0) + 1

    def prune_old(self, days):
        cutoff = time.time() - days * 86400
        try:
            with self._lock:
                conn = self._conn_open()
                for t in ("devices", "events", "dns_log", "flows"):
                    col = "ts" if t != "flows" else "first_ts"
                    conn.execute(f"DELETE FROM {t} WHERE {col} < ?", (cutoff,))
                conn.commit()
        except Exception:
            pass

    def _shrink(self):
        """体积超限: 保留 events 30%, 其余明细删一半最旧的, 再 VACUUM."""
        try:
            with self._lock:
                conn = self._conn_open()
                for t, col in (("dns_log", "ts"), ("flows", "first_ts"), ("devices", "ts")):
                    row = conn.execute(f"SELECT COUNT(*), MIN({col}) FROM {t}").fetchone()
                    if row and row[0] > 2000 and row[1]:
                        mid = row[1] + (time.time() - row[1]) / 2
                        conn.execute(f"DELETE FROM {t} WHERE {col} < ?", (mid,))
                conn.commit()
                conn.execute("VACUUM")
                conn.commit()
                self.log_event("system", "", "", "数据库超限, 已执行清理+VACUUM")
        except Exception:
            pass

    def db_size_mb(self):
        try:
            return os.path.getsize(self.db_path) / 1048576
        except Exception:
            return 0.0

    # ---------- 查询 (UI/导出用) ----------
    def query(self, table, where="1=1", args=(), order="ts DESC", limit=500):
        col = "ts" if table != "flows" else "first_ts"
        try:
            with self._lock:
                conn = self._conn_open()
                cur = conn.execute(
                    f"SELECT * FROM {table} WHERE {where} ORDER BY {col} DESC LIMIT ?",
                    (*args, int(limit)))
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, r)) for r in cur.fetchall()]
        except Exception:
            return []

    # ---------- CSV 导出 ----------
    def export_csv(self, table, start_ts, end_ts, out_path):
        """导出指定表时间范围数据 -> CSV (UTF-8 BOM, Excel 友好). 返回行数."""
        col = "ts" if table != "flows" else "first_ts"
        headers = {
            "devices": ["时间", "MAC", "IP", "事件"],
            "events": ["时间", "类型", "MAC", "IP", "消息"],
            "dns_log": ["时间", "MAC", "IP", "域名", "类型", "加密", "ECH", "应答IP"],
            "flows": ["开始", "结束", "MAC", "IP", "协议", "源端口", "目的端口", "对端",
                      "类别", "明细", "上行字节", "下行字节", "SNI", "ALPN", "JA3",
                      "ECH", "ESNI", "TLS版本", "DNS查询"],
        }.get(table)
        if not headers:
            raise ValueError(f"未知表: {table}")
        rows = self.query(table, f"{col} BETWEEN ? AND ?", (start_ts, end_ts),
                          order=f"{col} ASC", limit=1000000)
        with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                if table == "devices":
                    w.writerow([_fmt_ts(r["ts"]), r["mac"], r["ip"], r["event"]])
                elif table == "events":
                    w.writerow([_fmt_ts(r["ts"]), r["kind"], r["mac"], r["ip"], r["msg"]])
                elif table == "dns_log":
                    w.writerow([_fmt_ts(r["ts"]), r["mac"], r["ip"], r["qname"],
                                r["qtype"], "是" if r["encrypted"] else "否",
                                "是" if r["ech"] else "否", r["answers"]])
                elif table == "flows":
                    w.writerow([_fmt_ts(r["first_ts"]), _fmt_ts(r["last_ts"]), r["mac"],
                                r["ip"], {6: "TCP", 17: "UDP", 1: "ICMP"}.get(r["proto"], r["proto"]),
                                r["sport"], r["dport"], r["raddr"], r["category"], r["detail"],
                                r["bytes_up"], r["bytes_down"], r["sni"], r["alpn"], r["ja3"],
                                "是" if r["ech"] else "否", "是" if r["esni"] else "否",
                                r["tls_version"], r["qname"]])
        return len(rows)

    def close(self):
        self._stop.set()
        try:
            with self._lock:
                if self._conn:
                    self._conn.close()
                    self._conn = None
        except Exception:
            pass
