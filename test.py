# quick_test.py
import subprocess
import time


def quick_test():
    print("=" * 60)
    print("🧪 快速测试端口转发和代理")
    print("=" * 60)

    # 1. 设置端口转发
    print("\n1️⃣ 设置端口转发...")
    subprocess.run(["adb", "reverse", "--remove-all"], capture_output=True)
    result = subprocess.run(
        ["adb", "reverse", "tcp:8080", "tcp:8080"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("   ✅ 端口转发成功")

        # 查看规则
        check = subprocess.run(
            ["adb", "reverse", "--list"],
            capture_output=True,
            text=True
        )
        print(f"   规则: {check.stdout.strip()}")
    else:
        print(f"   ❌ 失败: {result.stderr}")
        return

    # 2. 设置代理
    print("\n2️⃣ 设置代理为 127.0.0.1:8080...")
    subprocess.run(
        ["adb", "shell", "settings put global http_proxy 127.0.0.1:8080"],
        capture_output=True
    )

    result = subprocess.run(
        ["adb", "shell", "settings get global http_proxy"],
        capture_output=True,
        text=True
    )
    print(f"   当前代理: {result.stdout.strip()}")

    # 3. 刷新网络
    print("\n3️⃣ 刷新网络...")
    subprocess.run(["adb", "shell", "su -c 'svc wifi disable'"], capture_output=True)
    time.sleep(2)
    subprocess.run(["adb", "shell", "su -c 'svc wifi enable'"], capture_output=True)
    print("   等待WiFi重连...")
    time.sleep(5)

    # 4. 测试连接
    print("\n4️⃣ 测试代理连接（确保mitmproxy正在运行）...")
    result = subprocess.run(
        ["adb", "shell", "curl -x http://127.0.0.1:8080 http://www.baidu.com -I -s -m 5"],
        capture_output=True,
        text=True,
        timeout=10
    )

    if "HTTP" in result.stdout:
        print("   ✅ 代理连接成功！")
        print(f"   响应: {result.stdout.split()[0:2]}")
    else:
        print("   ❌ 代理连接失败")
        print(f"   输出: {result.stdout[:200]}")
        print(f"   错误: {result.stderr[:200]}")

    print("\n" + "=" * 60)
    print("📋 下一步:")
    print("1. 如果测试成功，在模拟器浏览器访问 http://www.baidu.com")
    print("2. 在 http://127.0.0.1:8081 查看是否有流量")
    print("3. 然后打开APP测试")
    print("=" * 60)

    input("\n按Enter清除配置...")

    # 清理
    subprocess.run(["adb", "reverse", "--remove-all"], capture_output=True)
    subprocess.run(["adb", "shell", "settings delete global http_proxy"], capture_output=True)
    print("✅ 配置已清除")


if __name__ == "__main__":
    # 先确保mitmproxy在运行
    print("⚠️ 请先在另一个窗口启动mitmproxy:")
    print("   mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-port 8081")
    input("\n启动后按Enter继续...")

    quick_test()
