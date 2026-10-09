@echo off
REM ============================================================
REM  Self-AP-Monitor EXE 打包脚本 (PyInstaller)
REM  产物: dist\SelfAPMonitor.exe  (单文件, 启动时请求管理员权限)
REM  注意: EXE 用户仍需自行安装 Npcap 才能抓包 (见 docs/INSTALL.md)
REM ============================================================
setlocal
cd /d "%~dp0"

where python >nul 2>nul || (echo [错误] 未找到 python, 请先安装并加入 PATH & goto :fail)

echo [1/3] 安装/检查 PyInstaller ...
python -m pip install --quiet --upgrade pyinstaller || goto :fail

echo [2/3] 打包中 (首次约 1-3 分钟) ...
set OPTS=--noconfirm --clean --onefile --uac-admin --windowed ^
 --name SelfAPMonitor ^
 --collect-all scapy ^
 --collect-all cryptography ^
 --hidden-import scapy.layers.all

if exist bin\*.dll (
  echo       检测到 bin\*.dll, 一并打包 (nDPI)
  set OPTS=%OPTS% --add-binary "bin\*.dll;bin"
)

python -m PyInstaller %OPTS% main.py || goto :fail

echo [3/3] 完成
echo 产物: %cd%\dist\SelfAPMonitor.exe
echo 提示: 首次启动较慢(onefile 自解压); data\ 配置与数据库生成在 exe 同目录
exit /b 0

:fail
echo 打包失败, 请查看上方报错
exit /b 1
