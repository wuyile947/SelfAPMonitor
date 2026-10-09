"""Self-AP-Monitor: Windows 移动热点 元数据观测与管控工具 (仅限本人设备测试).

法律边界 (必须遵守):
  - 只做被动元数据采集 (五元组/字节数/DNS查询名/TLS握手明文字段)
  - 不做 HTTPS 解密、不做中间人、不伪造任何证书
  - 不注入伪造数据包
  - 仅允许在本人所有的设备与网络上测试使用
"""
__version__ = "1.0.0"
APP_NAME = "Self-AP-Monitor"

import os
import sys


def app_root():
    """程序根目录.

    脚本运行: 项目根目录; PyInstaller 打包后: exe 所在目录
    (onefile 模式下 __file__ 指向临时解压目录, 不能用于存放 data/)
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
