# client.py
import frida
import sys
import os
import subprocess
import time  # 用于adb操作后的短暂等待

# 定义输出文件名
OUTPUT_FILE = "packages.txt"

# --- 配置设备连接信息 ---
# 你的模拟器 ADB 连接地址
SIMULATOR_ADB_ADDRESS = ("192.168.1.102:5555")
# Frida Server 默认监听端口
FRIDA_SERVER_PORT = 27042
# 本地 Frida 客户端将通过 ADB 转发连接的端口
FRIDA_LOCAL_FORWARD_PORT = 27042

# 假设 frida-server 已经推送到 /data/local/tmp/frida-server
# 如果没有，你需要手动推送一次，或者在脚本中添加推送逻辑
FRIDA_SERVER_ANDROID_PATH = "/data/local/tmp/frida-server"

# 读取 Frida JS 脚本
script_dir = os.path.dirname(os.path.abspath(__file__))
js_file_path = os.path.abspath(os.path.join(script_dir, "..", "api_android_monitor", "agent.js"))

if not os.path.exists(js_file_path):
    print(f"错误: 找不到 Frida JS 脚本文件 -> {js_file_path}")
    sys.exit(1)

with open(js_file_path, 'r', encoding='utf-8') as f:
    js_code = f.read()

import json


def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('status') == 'success':
            try:
                # 从 payload 中获取 JSON 字符串并解析它
                package_names_json_str = payload['package_names_json_str']
                package_names = json.loads(package_names_json_str)  # 解析 JSON 字符串为 Python 列表

                print(f"成功获取 {len(package_names)} 个用户安装的应用包名。")
                # 写入文件
                with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    for pkg_name in package_names:
                        f.write(pkg_name + '\n')
                print(f"所有包名已成功写入到 '{OUTPUT_FILE}' 文件。")
                # 打印前20个预览
                print("\n前20个包名 (或更少):")
                for i, pkg_name in enumerate(package_names[:20]):
                    print(f"- {pkg_name}")
                if len(package_names) > 20:
                    print("...")
            except (KeyError, json.JSONDecodeError) as e:
                print(f"处理来自 Frida 的消息失败: {e}")
                print(f"收到的原始 Payload: {payload}")
                return
        else:
            print(f"Frida 脚本执行失败: {payload.get('message', '未知错误')}")
    elif message['type'] == 'error':
        print(f"[!] Frida Error: {message['description']}")

# --- adb_command 辅助函数 ---
def adb_command(args, check=True, capture_output=False, simulator_address=None):
    """
    Helper function to run adb commands.
    Args:
        args (list): List of command arguments.
        check (bool): If True, raise CalledProcessError on non-zero exit code.
        capture_output (bool): If True, capture stdout/stderr.
        simulator_address (str): If provided, add "-s S_ADDR" to the command.
    Returns:
        subprocess.CompletedProcess: Result of the command.
    """
    cmd = ["adb"]
    if simulator_address:
        cmd.extend(["-s", simulator_address])
    cmd.extend(args)

    print(f"执行 ADB 命令: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=capture_output, text=True, check=check, encoding='utf-8')
        if capture_output:
            return result
        return None  # Return None if not capturing output
    except FileNotFoundError:
        print("错误: 'adb' 命令未找到。请确保 Android Debug Bridge 已安装并添加到 PATH。")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ADB 命令执行失败: {' '.join(cmd)}\n错误: {e.stderr}")
        if capture_output:
            return e  # Return the exception object for error handling in caller
        sys.exit(1)
    except Exception as e:
        print(f"执行 ADB 命令时发生意外错误: {' '.join(cmd)}\n错误: {e}")
        sys.exit(1)


# --- pull_apk 函数 (再次确认使用 SIMULATOR_ADB_ADDRESS) ---
def pull_apk(package_name, output_dir="out"):
    """Pulls the APK for a given package name from the device."""
    print(f"尝试从 '{SIMULATOR_ADB_ADDRESS}' 拉取应用 '{package_name}' 的 APK...")
    try:
        # Find the path of the package
        result = adb_command(["shell", "pm", "path", package_name], capture_output=True,
                             simulator_address=SIMULATOR_ADB_ADDRESS)
        if hasattr(result, 'stderr') and result.stderr:  # Check if stderr exists and has content for errors
            print(f"错误: 获取包路径失败: {result.stderr.strip()}")
            return None

        apk_remote_path = result.stdout.strip()
        if not apk_remote_path.startswith("package:"):
            print(f"错误: 无法找到包 '{package_name}' 的路径。它是否已安装在设备上？输出: {apk_remote_path}")
            return None

        apk_remote_path = apk_remote_path.replace("package:", "")

        # Create local directory
        local_dir = os.path.join(output_dir, package_name)
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, f"{package_name}.apk")

        # Pull the APK
        print(f"发现 APK 路径: {apk_remote_path}")
        print(f"拉取到本地: {local_path}")
        adb_command(["pull", apk_remote_path, local_path], simulator_address=SIMULATOR_ADB_ADDRESS)

        print("APK 拉取成功。")
        return local_path

    except Exception as e:
        print(f"拉取 APK 时发生意外错误: {e}")
        return None


# --- 自动化 ADB 配置 ---
# --- 自动化 ADB 配置 ---
def setup_adb_for_frida():
    """
    自动化配置 ADB 连接并确保 frida-server 运行。
    此版本假设 frida-server 已存在于设备上，不再进行文件存在性检查。
    """
    print("--- 自动化配置 ADB 连接和 Frida Server ---")
    # 定义 frida-server 在设备上的标准路径
    FRIDA_SERVER_ANDROID_PATH = "/data/local/tmp/frida-server"
    # 1. 连接到模拟器
    print(f"1. 连接到 ADB 设备: {SIMULATOR_ADB_ADDRESS}")
    adb_command(["connect", SIMULATOR_ADB_ADDRESS], check=False)
    time.sleep(1)
    # 验证设备连接
    devices_result = adb_command(["devices"], capture_output=True, check=True)
    if SIMULATOR_ADB_ADDRESS not in devices_result.stdout:
        print(f"错误: 无法连接到设备 {SIMULATOR_ADB_ADDRESS}。请检查模拟器是否运行，或 IP 地址是否正确。")
        sys.exit(1)
    print(f"设备 {SIMULATOR_ADB_ADDRESS} 已连接。")
    # 2. 检查并启动 frida-server
    print(f"2. 检查并启动 Frida Server (路径: {FRIDA_SERVER_ANDROID_PATH})...")
    check_cmd = ["shell", "pgrep", "-f", FRIDA_SERVER_ANDROID_PATH]

    try:
        # 使用 subprocess.run 更灵活地处理命令输出
        result = subprocess.run(["adb", "-s", SIMULATOR_ADB_ADDRESS] + check_cmd, capture_output=True, text=True)

        if result.stdout.strip():
            print(f"Frida Server 已经在运行，PID: {result.stdout.strip()}")
        else:
            print("Frida Server 未运行，尝试启动...")
            # 直接尝试以 root 身份启动，不再检查文件是否存在
            start_cmd = ["shell", "su", "-c", f"'{FRIDA_SERVER_ANDROID_PATH} &'"]
            adb_command(start_cmd, simulator_address=SIMULATOR_ADB_ADDRESS, check=False)
            time.sleep(2)  # 等待 server 启动
            # 再次检查进程是否已启动
            result = subprocess.run(["adb", "-s", SIMULATOR_ADB_ADDRESS] + check_cmd, capture_output=True, text=True)
            if result.stdout.strip():
                print(f"Frida Server 成功启动，PID: {result.stdout.strip()}")
            else:
                print(f"错误: 启动 Frida Server 失败。")
                print("请在设备上确认以下几点:")
                print(f"1. '{FRIDA_SERVER_ANDROID_PATH}' 文件确实存在且为正确架构。")
                print(f"2. 文件具有执行权限 (可尝试手动执行 'su -c \"chmod +x {FRIDA_SERVER_ANDROID_PATH}\"')。")
                print("3. 模拟器已 root。")
                sys.exit(1)
    except Exception as e:
        print(f"检查或启动 frida-server 时发生意外错误: {e}")
        sys.exit(1)
    # 3. 设置 ADB 端口转发
    print(f"3. 设置 ADB 端口转发 (local:{FRIDA_LOCAL_FORWARD_PORT} -> remote:{FRIDA_SERVER_PORT})...")
    adb_command(["forward", f"tcp:{FRIDA_LOCAL_FORWARD_PORT}", f"tcp:{FRIDA_SERVER_PORT}"],
                simulator_address=SIMULATOR_ADB_ADDRESS)
    # 4. 验证端口转发是否成功
    forward_list_result = adb_command(["forward", "--list"], capture_output=True, check=True,
                                      simulator_address=SIMULATOR_ADB_ADDRESS)
    expected_forward_entry = f"tcp:{FRIDA_LOCAL_FORWARD_PORT} tcp:{FRIDA_SERVER_PORT}"
    if expected_forward_entry not in forward_list_result.stdout:
        print(f"错误: 端口转发设置失败。 'adb forward --list' 未包含 '{expected_forward_entry}'。")
        sys.exit(1)

    print(f"端口转发 {expected_forward_entry} 已成功设置。")
    print("--- ADB 配置完成 ---")


# --- 主程序逻辑 ---
if __name__ == "__main__":
    setup_adb_for_frida()  # 执行自动化 ADB 配置

    device = None
    try:
        # 'remote' 类型会自动检查本地的 127.0.0.1:27042 端口
        # 这个端口已经通过 adb forward 转发到了模拟器的 frida-server
        device = frida.get_usb_device()
        print(f"已成功连接到设备: {device.name} (ID: {device.id}, 类型: {device.type})")

        session = device.attach("system_server")
        print("已附加到 system_server 进程。")

        script = session.create_script(js_code)
        script.on('message', on_message)
        script.load()

        print("\nFrida 脚本已加载并执行。等待结果...")
        input("[+] 按 Enter 键退出...\n")

    except frida.core.RPCException as e:
        print(f"Frida RPC 错误 (连接、附件或脚本执行): {e}")
        print("可能原因:")
        print(f"- 1. Frida Server 可能在模拟器上崩溃或未成功启动 (尽管我们尝试了启动它)。")
        print(f"- 2. ADB 转发 {FRIDA_LOCAL_FORWARD_PORT}:{FRIDA_SERVER_PORT} 可能存在问题。")
        print(f"- 3. 'system_server' 进程不存在或无法访问（权限问题）。在模拟器上尝试 'frida-ps -U' 确认。")
        print(f"- 4. Frida Server 与客户端版本不匹配。")
        print(f"- 5. 脚本存在语法错误或运行时错误 (检查 on_message 的输出)。")
        sys.exit(1)
    except Exception as e:
        print(f"发生其他错误: {e}")
        sys.exit(1)

