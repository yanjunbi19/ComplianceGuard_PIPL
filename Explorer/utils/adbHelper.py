import os
import time
import subprocess
import re
import platform
import sys
from PIL import Image
import io

# ================= 路径自动适配 =================
# 自动定位 Explorer 根目录
CURRENT_FILE_PATH = os.path.abspath(__file__)
UTILS_DIR = os.path.dirname(CURRENT_FILE_PATH)
ROOT_DIR = os.path.dirname(UTILS_DIR)
PARENT_DIR = os.path.dirname(ROOT_DIR)

if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ================= 导入配置 =================
try:
    from Explorer.config import ADB_DEVICE
except ImportError:
    # 备用导入方案
    try:
        from config import ADB_DEVICE
    except ImportError:
        ADB_DEVICE = "127.0.0.1:5555"  # 默认兜底


def call_adb(command, deviceId=None):
    """
    执行adb命令，完美适配 Windows/Linux
    使用 subprocess.run 代替 Popen，更安全且易于处理编码
    """
    if deviceId is None:
        deviceId = ADB_DEVICE

    # 构建基础命令列表，避免使用 shell=True 带来的引号转义问题
    full_command = ["adb", "-s", deviceId] + command.split()

    try:
        # text=True 自动处理换行符, encoding 处理 Windows 编码
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=15
        )
        if result.returncode != 0 and result.stderr:
            # 某些命令（如 grep 没搜到）返回非0但不一定是错误，所以这里只做记录
            pass
        return result.stdout
    except Exception as e:
        print(f"❌ ADB command failed: {' '.join(full_command)} | Error: {e}")
        return ''


def checkPackageInstall(pkName):
    """
    检查应用是否已安装。
    💡 改进：不在 ADB 内部用 grep，而是拉回所有包名在 Python 内部判断，规避 Windows 无 grep 的问题。
    """
    stdout = call_adb('shell pm list packages')
    # 分行处理，精准匹配 package:com.xxx.xxx
    lines = stdout.splitlines()
    for line in lines:
        if line.strip() == f"package:{pkName}":
            return True
    return False


def clear(packageName):
    """清除应用数据"""
    return call_adb(f"shell pm clear {packageName}")


def selective_clear(package_name):
    """精细化网络重置"""
    print(f"🛠️ 正在为 {package_name} 执行精细化网络重置...")

    # 强杀 App
    call_adb(f"shell am force-stop {package_name}")
    time.sleep(1)

    trash_dirs = ["app_webview", "cache", "code_cache", "app_textures", "app_exec_lock"]

    for folder in trash_dirs:
        # 兼容 Windows 的引号处理
        path = f"/data/data/{package_name}/{folder}"
        cmd = f"shell su -c 'rm -rf {path}'"
        call_adb(cmd)
        print(f"  🗑️ 已清理: {folder}")

    print("✅ 精细化清理完成。")


def start_activity(activity):
    """启动Activity"""
    # 确保 activity 格式正确，如 com.package/.MainActivity
    call_adb(f"shell am start -n {activity}")


def get_current_activity():
    """获取当前处于前台的 Activity 名称"""
    # 这里的逻辑在 Python 层面过滤，不依赖 findstr 或 grep
    stdout = call_adb("shell dumpsys window windows")

    # 常见的匹配模式：mCurrentFocus 或 mFocusedApp
    patterns = [
        r'mCurrentFocus.+\{.+\s([^\s\/]+)\/([^\s\s\}]+)',
        r'mFocusedApp.+\{.+\s([^\s\/]+)\/([^\s\s\}]+)'
    ]

    for line in stdout.splitlines():
        if "mCurrentFocus" in line or "mFocusedApp" in line:
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    # 返回 Activity 类名
                    return match.group(2).strip()
    return None


def screencap(saveFile):
    """截屏并拉取到本地"""
    remote_file = "/data/local/tmp/screen.png"
    call_adb(f"shell screencap -p {remote_file}")

    # 确保 saveFile 的目录存在
    local_dir = os.path.dirname(os.path.abspath(saveFile))
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)

    # 执行 pull
    subprocess.run(["adb", "-s", ADB_DEVICE, "pull", remote_file, saveFile], capture_output=True)

    # 验证有效性
    try:
        with Image.open(saveFile) as img:
            img.verify()
    except:
        # 如果截图损坏，创建一个白板图
        img = Image.new("RGB", (1080, 1920), (255, 255, 255))
        img.save(saveFile)


def dump_layout(dump_file_path):
    """导出UI布局并读取"""
    remote_file = "/data/local/tmp/hierarchy.xml"
    call_adb(f"shell uiautomator dump {remote_file}")

    # 拉取到本地临时文件
    subprocess.run(["adb", "-s", ADB_DEVICE, "pull", remote_file, dump_file_path], capture_output=True)

    xml_content = ""
    if os.path.exists(dump_file_path):
        with open(dump_file_path, "r", encoding='utf-8', errors='ignore') as f:
            xml_content = f.read()
        try:
            os.remove(dump_file_path)
        except:
            pass
    return xml_content


# --- 保留原有函数名，确保外部调用不崩溃 ---
def force_stop(package):
    call_adb(f"shell am force-stop {package}")


def uninstallApp(pkName):
    call_adb(f"uninstall {pkName}")


def ls(path):
    res = call_adb(f"shell ls -d {path}")
    return "No such" not in res and res != ""


def pull(remote, local):
    subprocess.run(["adb", "-s", ADB_DEVICE, "pull", remote, local], capture_output=True)


def delete(filePath):
    call_adb(f"shell rm -rf {filePath}")
