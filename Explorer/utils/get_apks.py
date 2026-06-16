# puller.py
import os
import subprocess
import argparse
import sys
from pathlib import Path
import shutil

def check_adb_is_available():
    """检查 adb 命令是否可用"""
    try:
        # 运行一个无害的 adb 命令来检查其是否存在
        subprocess.run(["adb", "version"], check=True, capture_output=True)
        print("✅ ADB is available and connected.")
        return True
    except FileNotFoundError:
        print("❌ Error: 'adb' command not found. Please ensure ADB is installed and in your system's PATH.")
        return False
    except subprocess.CalledProcessError:
        print("❌ Error: ADB command failed. Is a device connected and authorized?")
        return False


def pull_package_apk(package_name: str, output_base_dir: str) -> bool:
    """
    从设备上拉取指定包名的 APK 文件 (只拉取 .apk，忽略 lib/oat 等).
    支持 Split APKs.

    Args:
        package_name: 应用的包名 (e.g., "com.example.app")
        output_base_dir: APK 文件存放的基础目录 (e.g., "apps")
    Returns:
        True 如果成功, False 如果失败.
    """
    print(f"\n--- Processing: {package_name} ---")
    try:
        # 1. 使用 `pm path` 找到 base.apk 的完整路径以定位远程目录
        path_cmd = ["adb", "shell", "pm", "path", package_name]
        result = subprocess.run(path_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode != 0 or not result.stdout:
            print(f"   [Error] Could not find path for package '{package_name}'. It might not be installed.")
            print(f"   ADB Stderr: {result.stderr.strip()}")
            return False
        apk_full_path = result.stdout.strip().replace("package:", "")
        remote_apk_dir = os.path.dirname(apk_full_path)
        if not remote_apk_dir:
            print(f"   [Error] Failed to parse remote directory from path: {apk_full_path}")
            return False
        # 2. 列出远程目录下的所有文件，并筛选出 .apk 文件
        list_cmd = ["adb", "shell", "ls", remote_apk_dir]
        list_result = subprocess.run(list_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')

        if list_result.returncode != 0:
            print(f"   [Error] Failed to list files in remote directory: {remote_apk_dir}")
            return False

        all_files = list_result.stdout.strip().splitlines()
        apk_files_to_pull = [f.strip() for f in all_files if f.strip().endswith('.apk')]
        if not apk_files_to_pull:
            print(f"   [Error] No APK files found in directory {remote_apk_dir}.")
            return False

        print(f"   Found {len(apk_files_to_pull)} APK file(s): {', '.join(apk_files_to_pull)}")
        # 3. 创建本地存储目录
        local_package_dir = Path(output_base_dir) / package_name
        local_package_dir.mkdir(parents=True, exist_ok=True)
        print(f"   Local destination: {local_package_dir}")
        # 4. 逐个拉取筛选出的 APK 文件
        for apk_file in apk_files_to_pull:
            # shell路径分隔符是'/'，即使在Windows上运行也是如此
            remote_file_path = f"{remote_apk_dir}/{apk_file}"
            local_file_path = local_package_dir / apk_file

            print(f"   Pulling '{apk_file}'...")
            pull_cmd = ["adb", "pull", remote_file_path, str(local_file_path)]

            pull_result = subprocess.run(pull_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if pull_result.returncode != 0:
                print(f"   [Error] Failed to pull file: {apk_file}")
                print(f"   ADB Stderr: {pull_result.stderr.strip()}")
                # 如果单个文件拉取失败，则将整个包标记为失败
                return False
        print(f"   ✅ Successfully pulled all APKs for {package_name}.")
        return True
    except Exception as e:
        print(f"   [Critical Error] An unexpected exception occurred: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Pull APKs from an Android device based on a list of package names.")
    parser.add_argument(
        "-f", "--file",
        default="packages.txt",
        help="Path to the text file containing package names, one per line. (default: packages_ap3.txt)"
    )
    parser.add_argument(
        "-o", "--output",
        default="G:\iie\mylab\guitest\Explorer/apps/ap6",
        help="The directory to save the pulled APK files. (default: apps)"
    )
    args = parser.parse_args()

    package_list_file = Path(args.file)
    output_dir = args.output

    if not package_list_file.is_file():
        print(f"Error: The specified file '{package_list_file}' does not exist.")
        sys.exit(1)

    if not check_adb_is_available():
        sys.exit(1)

    with open(package_list_file, 'r') as f:
        # 读取所有行，并去除空白和空行
        packages = [line.strip() for line in f if line.strip()]

    if not packages:
        print("The package list file is empty. Nothing to do.")
        return

    print(f"\nFound {len(packages)} packages to pull from '{package_list_file}'.")
    print(f"Output directory will be '{output_dir}'.")

    success_count = 0
    fail_count = 0

    for package in packages:
        if pull_package_apk(package, output_dir):
            success_count += 1
        else:
            fail_count += 1

    print("\n================= Summary ==================")
    print(f"Total Packages Processed: {len(packages)}")
    print(f"✅ Successful Pulls: {success_count}")
    print(f"❌ Failed Pulls:     {fail_count}")
    print("============================================")

def rename():
    # 配置路径
    source_dir = r"G:\iie\mylab\guitest\Explorer\apps\ap6"  # 原始父文件夹
    target_dir = r"G:\iie\mylab\guitest\Explorer\apps\ap6"  # 目标文件夹（存放重命名后的 APK）

    # 自动创建目标文件夹（如果不存在）
    os.makedirs(target_dir, exist_ok=True)

    # 遍历 source_dir 下的所有子项
    for item in os.listdir(source_dir):
        item_path = os.path.join(source_dir, item)

        # 只处理子文件夹
        if os.path.isdir(item_path):
            apk_path = os.path.join(item_path, "base.apk")

            # 检查 base.apk 是否存在
            if os.path.exists(apk_path):
                new_name = item + ".apk"  # 如 com.joltrix.bingoworld.apk
                target_path = os.path.join(target_dir, new_name)

                try:
                    # 移动并重命名
                    shutil.move(apk_path, target_path)
                    print(f"✅ 已移动: {item} → {new_name}")
                except Exception as e:
                    print(f"❌ 移动失败: {item}, 错误: {e}")
            else:
                print(f"⚠️ 跳过（无 base.apk）: {item}")

    print("\n🎉 所有操作完成！")
if __name__ == "__main__":
    #main()
    rename()