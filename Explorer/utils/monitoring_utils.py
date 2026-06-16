# utils/monitoring_utils.py

from loguru import logger
import os
import sys
import subprocess
import time
import platform

# ================= 路径自动适配 =================
# 获取当前文件 (monitoring_utils.py) 的绝对路径
CURRENT_FILE_PATH = os.path.abspath(__file__)
# 获取 utils 文件夹路径
UTILS_DIR = os.path.dirname(CURRENT_FILE_PATH)
# 获取根目录 Explorer 路径
ROOT_DIR = os.path.dirname(UTILS_DIR)
# 获取 Explorer 的父目录，以便支持 'from Explorer.xxx import yyy'
PARENT_DIR = os.path.dirname(ROOT_DIR)

if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ================= 导入模块 =================
try:
    from Explorer.monitoring.adb import ADB
    from androguard.core.bytecodes.apk import APK
    from Explorer.utils.adbHelper import start_activity, clear, checkPackageInstall, call_adb
    from Explorer.utils.suppress_stdout import suppress_stdout_stderr
    from Explorer.config import ADB_DEVICE
except ImportError as e:
    logger.error(f"导入模块失败，请检查包结构: {e}")
    # 备用方案：如果作为脚本独立运行，尝试直接导入
    from monitoring.adb import ADB
    from utils.adbHelper import start_activity, clear, checkPackageInstall, call_adb
    from utils.suppress_stdout import suppress_stdout_stderr
    from config import ADB_DEVICE


def get_grep_command():
    """获取平台对应的 grep 命令 (虽然我们在 Python 内部过滤，但保留此函数以备不时之需)"""
    return 'findstr' if platform.system() == 'Windows' else 'grep'


def check_frida_server_running() -> bool:
    """
    检查 frida-server 是否运行。
    改用端口检测 (27042)，这是最准确的方法。
    """
    try:
        # 检查 27042 端口是否在监听
        result = subprocess.run(
            ["adb", "-s", ADB_DEVICE, "shell", "netstat -tulpn"],
            capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
        )

        # 如果端口被占用，说明 frida 已启动
        if ":27042" in result.stdout or "0.0.0.0:27042" in result.stdout or "127.0.0.1:27042" in result.stdout:
            return True

        # 备选方案：如果 netstat 不好使，搜一下进程名（模糊搜索）
        res_ps = subprocess.run(
            ["adb", "-s", ADB_DEVICE, "shell", "ps -A"],
            capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
        )
        if "hluda-server" in res_ps.stdout or "frida-server" in res_ps.stdout:
            return True

        return False
    except Exception as e:
        logger.warning(f"检测 Frida 状态失败: {e}")
        return False


def check_remote_file_exists(adb: ADB, remote_path: str) -> bool:
    """通过 adb shell 检查远程文件是否存在"""
    try:
        # 使用最通用的 ls 命令
        res = subprocess.run(
            ["adb", "-s", ADB_DEVICE, "shell", f"ls {remote_path}"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8',
            errors='ignore'
        )
        output = res.stdout.strip()
        if "No such file" in output or "Permission denied" in output:
            return False
        return remote_path in output
    except Exception:
        return False


def ensure_adb_connected(device_address):
    """确保 ADB 处于连接状态"""
    try:
        res = subprocess.run(["adb", "-s", device_address, "get-state"],
                             capture_output=True, text=True, timeout=5, encoding='utf-8')
        if "device" in res.stdout:
            return True

        logger.warning(f"⚠️ 设备 {device_address} 离线，正在尝试重新连接...")
        subprocess.run(["adb", "disconnect", device_address], capture_output=True)
        time.sleep(1)
        res = subprocess.run(["adb", "connect", device_address], capture_output=True, text=True, timeout=10)

        if "connected" in res.stdout or "already" in res.stdout:
            time.sleep(2)
            return True
    except Exception as e:
        logger.error(f"ADB 连接检查异常: {e}")
    return False


def push_and_start_frida_server(adb: ADB):
    """推送并启动 frida-server"""
    device_addr = ADB_DEVICE
    if not ensure_adb_connected(device_addr):
        raise RuntimeError(f"无法连接到 ADB 设备: {device_addr}")
    frida_server_local_path = os.path.normpath(os.path.join(ROOT_DIR, "resources", "frida-server", "hluda-server"))
    remote_path = "/data/local/tmp/hluda-server"

    # 如果已经运行了，直接返回
    if check_frida_server_running():
        logger.info("✅ frida-server 已经在运行中。")
        return
    # 获取 root 权限
    is_rooted = False
    try:
        subprocess.run(["adb", "-s", device_addr, "root"], capture_output=True, timeout=5)
        res = subprocess.run(["adb", "-s", device_addr, "shell", "su -c 'id'"], capture_output=True, text=True)
        if "uid=0" in res.stdout.lower():
            is_rooted = True
    except:
        pass
    # 推送和授权
    if not check_remote_file_exists(adb, remote_path):
        logger.info("推送 hluda-server...")
        subprocess.run(["adb", "-s", device_addr, "push", frida_server_local_path, remote_path], check=True)

    subprocess.run(["adb", "-s", device_addr, "shell", f"su -c 'chmod 777 {remote_path}'"])
    # 启动
    for attempt in range(3):
        logger.info(f"🚀 启动 frida-server (第 {attempt + 1} 次尝试)...")
        # 使用 exec 启动可以避免产生多余的 shell 进程
        start_cmd = f"su -c 'exec {remote_path} > /dev/null 2>&1 &'"
        subprocess.run(["adb", "-s", device_addr, "shell", start_cmd])

        time.sleep(3)
        if check_frida_server_running():
            logger.info("✅ frida-server 启动成功。")
            return
    raise RuntimeError("无法启动 Frida server，端口 27042 仍未响应。")


# def check_close_frida(adb):
#     """
#     更强力的关闭逻辑：直接杀掉占用 27042 端口的进程
#     """
#     logger.info("正在清理已有的 Frida 进程...")
#     try:
#         # 1. 尝试通过 pkill 杀掉所有可能的名字
#         names = ["hluda-server", "frida-server", "frida-helper"]
#         for name in names:
#             subprocess.run(["adb", "-s", ADB_DEVICE, "shell", f"pkill -9 {name}"], capture_output=True)
#             subprocess.run(["adb", "-s", ADB_DEVICE, "shell", f"su -c 'pkill -9 {name}'"], capture_output=True)
#         # 2. 进阶：通过端口查找 PID 并杀掉
#         # 查找监听 27042 的 PID
#         cmd = "netstat -tulpn | grep :27042"
#         res = subprocess.run(["adb", "-s", ADB_DEVICE, "shell", f"su -c '{cmd}'"], capture_output=True, text=True)
#
#         # 解析 PID (netstat 输出格式通常是 ... PID/Program)
#         output = res.stdout.strip()
#         if output and "/" in output:
#             try:
#                 # 提取 PID
#                 parts = output.split()
#                 pid_part = [p for p in parts if "/" in p][0]
#                 pid = pid_part.split('/')[0]
#                 if pid.isdigit():
#                     logger.info(f"杀掉占用端口的进程 PID: {pid}")
#                     subprocess.run(["adb", "-s", ADB_DEVICE, "shell", f"su -c 'kill -9 {pid}'"], capture_output=True)
#             except:
#                 pass
#
#         time.sleep(1)
#         logger.info("✅ Frida 进程清理完成")
#     except Exception as e:
#         logger.warning(f"清理 Frida 进程失败: {e}")
def check_close_frida(device_id):
    """
    针对 Windows 环境优化的强力清理逻辑
    """
    logger.info(f"正在深度清理设备 {device_id} 上的 Frida 残留...")

    # 1. 定义需要清理的进程关键词
    targets = ["hluda-server", "frida-server", "frida-helper", "frida-agent"]

    try:
        # 2. 获取所有进程列表 (使用 ps -A 兼容 Android 10+)
        # 在 Windows 上，我们将整个命令作为字符串发送
        cmd = f"adb -s {device_id} shell \"su -c 'ps -A'\""
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

        # 如果 ps -A 失败，尝试普通的 ps
        if not result.stdout.strip():
            cmd = f"adb -s {device_id} shell \"su -c 'ps'\""
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        lines = result.stdout.splitlines()
        pids_to_kill = set()
        # 3. 扫描包含关键词的 PID
        for line in lines:
            for target in targets:
                if target in line:
                    parts = line.split()
                    if len(parts) > 1:
                        # 通常 PID 在第二列
                        pid = parts[1]
                        if pid.isdigit():
                            pids_to_kill.add(pid)
        # 4. 逐个强力杀掉进程
        if pids_to_kill:
            logger.info(f"发现残留进程 PID: {pids_to_kill}，准备清理...")
            for pid in pids_to_kill:
                kill_cmd = f"adb -s {device_id} shell \"su -c 'kill -9 {pid}'\""
                subprocess.run(kill_cmd, shell=True, capture_output=True)
            logger.success("✅ 残留进程已清理")
        else:
            logger.info("未发现运行中的 Frida 相关进程")
        # 5. 额外保险：尝试直接根据端口释放 (针对某些占用端口但搜不到进程的情况)
        # 注意：Android 的 lsof 往往在 /system/bin/lsof 或需通过 busybox
        # 这里用一个小技巧：尝试再次运行 pkill (即使它可能不存在)
        for target in targets:
            subprocess.run(f"adb -s {device_id} shell \"su -c 'pkill -9 {target}'\"", shell=True, capture_output=True)
        time.sleep(1)

    except Exception as e:
        logger.error(f"清理 Frida 失败: {e}")

def read_api_to_monitoring(file_api_to_monitoring):
    """读取 API 监控列表，增加对 Windows 默认编码的防御"""
    if not os.path.exists(file_api_to_monitoring):
        return None

    list_api_to_monitoring = []
    # 必须指定 utf-8 编码，否则 Windows 会用 GBK 报错
    with open(file_api_to_monitoring, 'r', encoding='utf-8') as f:
        content = [x.strip() for x in f.readlines() if x.strip()]

    for line in content:
        try:
            # 兼容 "类名,方法名|备注" 和 "类名,方法名"
            base_part = line.split('|')[0] if '|' in line else line
            if ',' in base_part:
                clazz, method = base_part.split(',')
                list_api_to_monitoring.append((clazz.strip(), method.strip()))
        except Exception as e:
            logger.error(f"解析行失败: {line}, 错误: {e}")

    return list_api_to_monitoring


def create_script_frida(list_api_to_monitoring: list, path_frida_script_template: str):
    """创建 frida 脚本"""
    if not os.path.exists(path_frida_script_template):
        logger.error(f"找不到模板文件: {path_frida_script_template}")
        return ""

    with open(path_frida_script_template, 'r', encoding='utf-8') as f:
        template = f.read()

    scripts = []
    for clazz, method in list_api_to_monitoring:
        scripts.append(template.replace("class_name", f'"{clazz}"').replace("method_name", f'"{method}"'))

    return "\n\n".join(scripts)


def create_list_api_from_file(list_file_api_to_monitoring):
    """从文件创建API列表"""
    list_api_to_monitoring_complete = list()
    for file_api_to_monitoring in list_file_api_to_monitoring:
        list_api_to_monitoring = read_api_to_monitoring(file_api_to_monitoring)
        list_api_to_monitoring_complete.extend(list_api_to_monitoring)
    return list_api_to_monitoring_complete

# ================= 其余函数保持逻辑一致 =================
def install_app_and_install_frida(app_path, pkName, activityName):
    adb = ADB()
    if not checkPackageInstall(pkName):
        logger.info(f"正在安装应用: {pkName}")
        subprocess.run(["adb", "-s", ADB_DEVICE, "install", "-r", app_path], capture_output=True)

    check_close_frida(adb)
    push_and_start_frida_server(adb)
    return APK(app_path).get_package()


def install_frida(app_path, pkName, activityName):
    adb = ADB()
    check_close_frida(adb)
    push_and_start_frida_server(adb)
    return APK(app_path).get_package()


def create_adb_and_start_frida(package_name):
    adb = ADB()
    push_and_start_frida_server(adb)
    return package_name


def create_json_custom(list_api_to_monitoring):
    hooks = [{"clazz": api[0], "method": api[1]} for api in list_api_to_monitoring]
    return {"Category": "Custom", "HookType": "Java", "hooks": hooks}
