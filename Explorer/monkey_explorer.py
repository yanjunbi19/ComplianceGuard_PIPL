import os
import argparse
import time
import subprocess
import gc
import pickle
from datetime import datetime
from loguru import logger

# 导入你原有的组件
import config
from utils import apk_util
from utils.general_util import scan_file
from utils.adbHelper import force_stop
from utils.network import Monitor
from utils.driver_manager import driver_manager
from utils.screen_util import save_gui_image, save_json_file
from RLApplicationEnv import RLApplicationEnv

ADB_DEVICE = config.ADB_DEVICE


def main():
    parser = argparse.ArgumentParser(description='Monkey Explorer')
    parser.add_argument('--apps', type=str, default='apps/ap')
    parser.add_argument('--total_events', type=int, default=40)
    parser.add_argument('--burst_size', type=int, default=100)
    parser.add_argument('--throttle', type=int, default=300)
    parser.add_argument('--algo', type=str, default='random')
    parser.add_argument('--num_actions', type=int, default=100)
    parser.add_argument('--stage', type=int, default=1)
    args = parser.parse_args()

    apks = scan_file(args.apps)
    driver_manager.init(ADB_DEVICE)

    for application in apks:
        if not application.endswith(".apk"): continue

        app_name = os.path.basename(os.path.splitext(application)[0])

        # ✅ 重要：每轮开始前强制重置全局 Frida 状态
        config.frida_ready = False
        config.thread_life = True

        raw_activity_info = {}
        appPackage, appActivity, _ = apk_util.parse_pkg(application, raw_activity_info)
        all_activities_list = list(raw_activity_info.keys())

        logger.info(f"🚀 ================== 启动任务: {app_name} ==================")

        output_dir = os.path.join("analysis", "monkey", app_name)
        os.makedirs(output_dir, exist_ok=True)
        network_monitor = Monitor(appPackage, app_name, ADB_DEVICE, output_base_dir=output_dir, algo="monkey")
        network_monitor.start_monitoring(stage=args.stage)

        app = None
        try:
            # --- 初始化环境 ---
            # 增加超时宽容度：内部 __init__ 可能需要很久
            app = RLApplicationEnv(
                params=args,
                appPackage=appPackage,
                appActivity=appActivity,
                application=application,
                bert=None,
                layout_autoencoder=None,
                vtr=None,
                allActivities=all_activities_list,
                device_address=ADB_DEVICE
            )

            # --- 核心 Monkey 逻辑 ---
            logger.info(f"🟢 App 已就绪，开始 Monkey 探测...")
            total_bursts = args.total_events // args.burst_size

            for burst_idx in range(1, total_bursts + 1):
                logger.info(f"🌀 {app_name} | 进度: {burst_idx}/{total_bursts}")

                # 确保 App 在前台
                driver_manager.ensure_app_running(appPackage, appActivity, app)

                # 执行 Monkey
                cmd = f"adb -s {ADB_DEVICE} shell monkey -p {appPackage} --throttle {args.throttle} --ignore-crashes --ignore-timeouts --ignore-security-exceptions --pct-syskeys 0 -v {args.burst_size}"
                subprocess.run(cmd, shell=True, capture_output=True)

                # 提取 API
                sens_apis = app.checkSensitiveAPIs()
                if sens_apis:
                    logger.warning(f"🚩 发现 {len(sens_apis)} 个 API 调用")
                    app.all_sensitive_api_list.extend(sens_apis)

                    ts = datetime.now().strftime("%Y%m%d%H%M%S")
                    dump_path = os.path.join("dumps", appPackage, f"{ts}_BURST_{burst_idx}")
                    os.makedirs(dump_path, exist_ok=True)
                    try:
                        screen = app.dm.screenshot()
                        save_gui_image(path=dump_path, img_dict={'ui': screen}, scale=0.3)
                    except:
                        pass
                    save_json_file(path=dump_path, json_dict={'api_name_list': sens_apis})

                if not app.monitoring_thread.is_alive():
                    logger.error("🚨 Frida 线程丢失，跳过此 App")
                    break

        except Exception as e:
            logger.error(f"❌ 运行异常: {e}")
        finally:
            if network_monitor.is_monitoring:
                network_monitor.stop_monitoring()
            if app:
                force_stop(appPackage)
            config.thread_life = False
            config.frida_ready = False  # 重置状态给下一个 APK
            gc.collect()
            time.sleep(2)  # 缓冲


if __name__ == '__main__':
    main()
