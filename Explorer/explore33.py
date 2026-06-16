import os
import argparse
from utils import apk_util
from loguru import logger
from RLApplicationEnv_abl import RLApplicationEnv
from utils.general_util import scan_file
from threading import Thread
from monitoring import papi_monitor
import config
from pathlib import Path
import traceback
from utils.adbHelper import start_activity
import time
import random
import torch
import numpy as np
from utils.sys_util import restart_app, exception_process, app_refresh
from utils.adbHelper import force_stop, clear, uninstallApp,selective_clear
import subprocess
from consist.api_descriptions import get_api_descriptions
from utils.screen_util import save_gui_image, save_json_file, save_xml_file
from utils.thread_kill import stop_thread
from utils.recorder import ExperimentRecorder
from utils.suppress_stdout import suppress_stdout_stderr
import gc
import pickle
from datetime import datetime
import io
from utils.wifi_util import get_wifi_state, restart_wifi
from utils.general_util import parse_pages
from loguru import logger
from utils.network import Monitor
import sys
from utils.driver_manager import driver_manager
import shutil


ADB_DEVICE = config.ADB_DEVICE

script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

seed = 1234
random.seed(seed)
np.random.seed(seed)
torch.cuda.manual_seed_all(seed)
torch.manual_seed(seed)


def common_ops(appPackage, app_name):
    gc.collect()
    config.thread_life = True
    config.TIMER = None
    force_stop(appPackage)



def main():
    parser = argparse.ArgumentParser(description='sensitive api monitoring demo')
    parser.add_argument('--iterations', type=int, default=10)
    parser.add_argument('--episods', type=int, default=1)
    parser.add_argument('--algo', choices=['dqn', 'sac', 'random', 'Q'], type=str, default='sac')
    parser.add_argument('--platform_name', choices=['Android', 'iOS'], type=str, default='Android')
    parser.add_argument('--platform_version', type=str, default='12')
    parser.add_argument('--udid', type=str, default='a6a635a42b72c75b')  # 默认udid
    parser.add_argument('--device_name', type=str, default='Pixel5')
    parser.add_argument('--android_port', type=str, default='5554')  # 模拟器端口
    parser.add_argument('--apps', type=str, default='apps/testapp')
    parser.add_argument('--apps_explored', type=str, default='apps/testapp1')
    parser.add_argument('--layout_model', type=str, default=None)
    parser.add_argument('--memory_capacity', type=int, default=32)  # DQN使用，SAC可能不直接使用
    parser.add_argument('--num_actions', type=int, default=200)  # 动作空间大小
    parser.add_argument('--stage', type=int, default=2, help='1: Unlogged stage, 2: Logged stage')
    args = parser.parse_args()
    N = args.iterations
    episods = args.episods
    algo = args.algo
    apks = scan_file(args.apps)

    logger.info(f"🚀 算法已就绪: {algo} | 阶段: {args.stage}")

    driver_manager.init(ADB_DEVICE, auto_restart_uia=False)

    try:
        for i, application in enumerate(apks):

            app_name = os.path.basename(os.path.splitext(application)[0])

            model = None
            if algo in ['dqn', 'Q']:
                from models.dqn import DQN
                model = DQN()
            elif algo == 'sac':
                from models.sac import SACModel
                model = SACModel(num_actions=args.num_actions)

            logger.info(f"App {app_name}: 使用全新 {algo} 模型")

            raw_activity_info = {}
            appPackage, appActivity, _ = apk_util.parse_pkg(application, raw_activity_info)
            logger.info("appPackage:" + str(appPackage))
            logger.info("appActivity:" + str(appActivity))
            all_activities_list = list(raw_activity_info.keys())  # ✅ 移到

            app_success_flag = False  # ✅ 初始化成功标记
            failure_reason = "Unknown"
            output_dir = os.path.join("analysis", algo, app_name)
            os.makedirs(output_dir, exist_ok=True)
            lock_file = os.path.join(output_dir, "2nd.lock")

            logger.info(f"🧹 正在为新任务 {app_name} 清理环境...")
            try:
                subprocess.run(
                    f"adb -s {ADB_DEVICE} shell \"pkill -9 frida; pkill -9 uiautomator; pkill -9 atx-agent\" > /dev/null 2>&1",
                    shell=True)

                _ = driver_manager._driver.info

                driver_manager.app_stop(appPackage)

            except Exception as e:
                logger.warning(f"⚠️ 驱动响应异常或环境损坏 ({e})，触发深度重置...")
                reset_infrastructure(ADB_DEVICE)
                try:
                    driver_manager.app_stop(appPackage)
                except:
                    pass
            if args.stage == 1:
                if os.path.exists(lock_file): os.remove(lock_file)
                driver_manager.shell(f"pm clear {appPackage}")
                logger.info(f"✨ 阶段 1：准备全新探测 {appPackage}")


            else:
                logger.info(f"🔐 阶段 2：准备带登录态探测 {appPackage}")
                with open(lock_file, 'w') as f:
                    f.write("lock")

            network_monitor = Monitor(appPackage, app_name, ADB_DEVICE, output_base_dir=output_dir, algo=algo)
            monitor_started = network_monitor.start_monitoring(stage=args.stage)

            try:
                config.thread_life = True
                app = RLApplicationEnv(
                    params=args,  # 内部包含 stage 逻辑
                    appPackage=appPackage,
                    appActivity=appActivity,
                    application=application,
                    bert=model.bert if model else None,
                    layout_autoencoder=model.layout_autoencoder if model else None,
                    vtr=model.vtr if model else None,
                    allActivities=all_activities_list,
                    device_address=ADB_DEVICE
                )

                if args.stage == 1:
                    logger.info(
                        f"🛡️ [Audit] 正在追溯启动阶段 ({app.app_start_time if hasattr(app, 'app_start_time') else 'Startup'}) 的 API 调用...")

                    startup_silent_apis = app.checkSensitiveAPIs()

                    if startup_silent_apis:
                        logger.warning(f"🚩 发现【启动阶段】静默上传！共 {len(startup_silent_apis)} 个 API")
                        app.all_sensitive_api_list.extend(startup_silent_apis)

                        os.makedirs(f'dumps/{app.appPackage}', exist_ok=True)
                        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                        save_path = f"dumps/{app.appPackage}/{timestamp}_STARTUP_SILENT"
                        os.makedirs(save_path, exist_ok=True)

                        save_json_file(path=save_path, json_dict={
                            'api_name_list': startup_silent_apis,
                            'stage': 'startup_silent',
                            'description': 'Detected immediately after app spawn and before any UI interaction'
                        })
                else:
                    logger.info("🔐 阶段 2：跳过启动同意前 API 检测。")
            except RuntimeError as e:
                logger.error(f"💥 App {app_name} 初始化失败，跳过。错误: {e}")
                record_status(app_name, "failed", f"Init RuntimeError: {e}")  # ✅ 记录失败

                if network_monitor.is_monitoring:
                    network_monitor.stop_monitoring()
                driver_manager.app_stop(appPackage)
                continue  # 跳到下一个 App

            except Exception as e:
                error_traceback = traceback.format_exc()

                logger.error(f"💥 App {app_name} 初始化失败 (通用异常)")
                logger.error(f"   错误类型: {type(e).__name__}")
                logger.error(f"   错误信息: {e}")
                logger.error(f"   完整堆栈:\n{error_traceback}")
                record_status(app_name, "failed", f"Init Exception: {type(e).__name__}")
                if network_monitor.is_monitoring:
                    network_monitor.stop_monitoring()
                driver_manager.app_stop(appPackage)
                continue  # 跳到下一个 App

            W_api = 12.0  # 固定 API 奖励
            R_new = 10.0  # 强化新页面探索
            W_wid = 0.5  # 强化微观探索
            R_escape = 12.0  # 强化脱困奖励
            P_red = -15.0  # 强化卡死惩罚 (基础值)
            R_old = -2.0  # 弱化步数惩罚

            weights = {
                'api': W_api, 'new': R_new, 'red': P_red,
                'old': R_old, 'esc': R_escape, 'wid': W_wid
            }
            recorder = ExperimentRecorder(app_name, algo, args.stage, weights)

            START_PAGE_FLAG = True
            coverage_rate = 0.0
            max_allowed_crashes = 6
            try:
                for episod in range(episods):
                    cycle = 0  # ✅ 每个 episode 重置
                    crash_counter = 0  # ✅ 每个 episode 初始化
                    consecutive_stuck_count = 0
                    driver_manager.ensure_app_running(appPackage, appActivity, app)
                    handle_agreement_gate(app, collect_pre_consent=(args.stage == 1))  # 自动处理隐私协议

                    while cycle < N:
                        action = None  # ✅ 每轮先定义，避免引用未定义
                        operatable_widget = None
                        current_pkg = "unknown"
                        try:
                            current_pkg = app.dm.app_current().get('package', 'unknown')
                        except:
                            pass
                        if current_pkg != appPackage:
                            crash_counter += 1
                            logger.warning(f"⚠️ App 退出前台 ({crash_counter}/{max_allowed_crashes})")
                            if crash_counter >= max_allowed_crashes:
                                logger.error(f"❌ App {app_name} 稳定性太差，已达到崩溃上限，跳过该任务")
                                app_success_flag = False
                                failure_reason = "Too many crashes or Anti-Frida triggered"
                                break
                            driver_manager.ensure_app_running(appPackage, appActivity, app)
                            time.sleep(3)
                            continue
                        else:
                            crash_counter = 0
                        info = {'is_stuck': False, 'api_list': [], 'state_id': ''}
                        done = False
                        if cycle % 50 == 0:  # ✅ 不依赖 action is None
                            driver_manager.ensure_app_running(appPackage, appActivity, app)
                        cycle += 1
                        current_state = app.observation
                        try:
                            if algo == 'random':
                                if len(app.usable_widgets) > 0:
                                    action = random.randint(0, len(app.usable_widgets) - 1)
                                    operatable_widget = app.all_widget_dict[app.usable_widgets[action]]
                            else:
                                chosen = model.choose_action(app)
                                if chosen:
                                    current_state, action, operatable_widget = chosen
                        except Exception as e:
                            logger.error(f"决策异常: {e}")
                            START_PAGE_FLAG = driver_manager.ensure_app_running(appPackage, appActivity, app)
                            continue
                        if operatable_widget:
                            try:
                                next_state, reward, done, info_result = app.step(operatable_widget)
                                if next_state is None:
                                    logger.warning("App step returned None. Skipping learning and data recording.")
                                    START_PAGE_FLAG = driver_manager.ensure_app_running(appPackage, appActivity, app)
                                    continue
                                info = info_result
                                recorder.record_step(
                                    step=cycle,
                                    reward=reward,
                                    api_list=info.get('api_list', []),
                                    activity=info.get('activity', 'unknown'),
                                    is_stuck=info.get('is_stuck', False),
                                    recovered=info.get('recovered', False),
                                    xml_score=info.get('xml_score', 0.0),
                                    img_same=info.get('img_same', False),
                                    input_performed=info.get('input_performed', False),
                                    reward_debug=info.get('reward_debug', ""),
                                )
                                if algo != 'random':
                                    if model and hasattr(model, 'store_transition'):
                                        if algo in ['dqn', 'Q']:
                                            model.store_transition(current_state, action, next_state, reward)
                                        else:
                                            model.store_transition(current_state, action, next_state, reward, done)
                                    if model and cycle % 20 == 0:
                                        model.learn('currentApp')
                            except Exception as e:
                                logger.error(f"动作执行失败: {e}")
                                START_PAGE_FLAG = driver_manager.ensure_app_running(appPackage, appActivity, app)
                                continue
                        else:
                            logger.warning("无可用组件，尝试 Back 键跳出")
                            driver_manager.press("back")
                            app.refreshNewObservation()
                        total_count = len(all_activities_list)
                        coverage_rate = len(app.GUI_dict) / total_count if total_count > 0 else 0
                        logger.info(
                            f'[{algo}-S{args.stage}] {app_name} | Cycle: {cycle}/{N}. '
                            f'Activity coverage rate is: {coverage_rate:.4f} ({len(app.GUI_dict)}/{total_count})'
                        )
                        if info.get('is_stuck', False):
                            consecutive_stuck_count += 1
                        else:
                            consecutive_stuck_count = 0
                        if consecutive_stuck_count >= 3:
                            logger.info("🤖 发现轻微卡顿，尝试 Back 键脱困")
                            driver_manager.press("back")
                            app.refreshNewObservation()
                            consecutive_stuck_count = 0
                        if done:
                            logger.warning(
                                "🚨 Episode done (env unstable/crash/stuck). Skip this app without hard reset.")
                            app_success_flag = False
                            failure_reason = "Episode terminated (monitoring died / stuck / crash)"
                            break
                    if crash_counter >= max_allowed_crashes:
                        break  # 跳出 episod 循环，直接进入该 app 的收尾逻辑
                app_success_flag = True
            except Exception as e:
                failure_reason = f"Exploration Error: {str(e)[:50]}"
                logger.error(f"探索过程中发生异常: {e}")
                app_success_flag = False
            if app_success_flag:
                record_status(app_name, "success")
                explored_dir = Path(args.apps_explored)
                explored_dir.mkdir(parents=True, exist_ok=True)
                source_apk = Path(application)
                target_apk = explored_dir / source_apk.name
                if source_apk.exists():
                    shutil.move(str(source_apk), str(target_apk))
                else:
                    logger.warning(f"探索成功，但未找到待移动 APK: {source_apk}")
            else:
                record_status(app_name, "failed", failure_reason)

            with open("coverage.txt", 'a', encoding='utf-8') as f:
                f.write(f"App: {app_name} | Algo: {algo} | Stage: {args.stage} | Coverage: {coverage_rate:.4f}\n")

            config.thread_life = False
            if network_monitor.is_monitoring:
                network_monitor.stop_monitoring()
            try:
                if hasattr(app, "monitoring_thread") and app.monitoring_thread and app.monitoring_thread.is_alive():
                    app.monitoring_thread.join(timeout=3)
            except Exception as e:
                logger.warning(f"monitoring_thread join failed: {e}")
            logger.info(f"✅ App {app_name} 分析完成")
            if 'app' in locals() and app is not None and appPackage:
                safe_stop_app(appPackage, app_name)
    except Exception as e:
        logger.error(f"❌ 严重运行异常: {traceback.format_exc()}")
    finally:
        config.thread_life = False
        logger.info("🏁 任务结束，环境已清理。")

def safe_stop_app(appPackage, app_name):
    try:
        driver_manager.app_stop(appPackage)  # uiautomator2 stop
        time.sleep(0.8)
        logger.info(f"🛑 App {app_name} stop issued.")
        return True
    except Exception as e:
        logger.warning(f"⚠️ App {app_name} stop failed, sfip teardown: {e}")
        return False

def handle_agreement_gate(app, collect_pre_consent=True):
    """
    自动处理启动时的同意/引导界面，同时捕获在此期间触发的敏感 API。
    """
    max_gates = 5
    for i in range(max_gates):
        try:
            if not app.monitoring_thread.is_alive():
                logger.error("🚨 Gate Handler 检测到 Frida 线程死亡，立即终止 App 探索。")
                raise RuntimeError("Frida monitoring thread died during gate handling.")
            if app.observation is None or len(app.observation[2][0]) == 0:
                logger.debug(f"第 {i + 1} 层：无更多明显弹窗或组件，退出 Gate 循环。")
                break  # 没有 UI 元素了，跳出循环
            agree_widget, widget_type = parse_pages(app.observation[2][0])

            if agree_widget is not None:
                pre_click_apis = app.checkSensitiveAPIs() if collect_pre_consent else []
                if pre_click_apis:
                    logger.warning(f"同意按钮点击前触发 API: {pre_click_apis}")
                    app.all_sensitive_api_list.extend(pre_click_apis)
                elif not collect_pre_consent:
                    logger.info("🔐 阶段 2：跳过同意按钮点击前 API 检测。")

                old_gui = app.last_screenshot
                old_xml = app.last_page_source

                logger.info(f"🎯 Found Gate! Clicking/Swiping at {agree_widget}")
                if widget_type == False:  # 点击类型
                    app.dm.click(int(agree_widget[0]), int(agree_widget[1]))
                else:  # 滑动类型
                    app.dm.swipe(950, int(agree_widget[1]), 100, int(agree_widget[1]))

                time.sleep(1.0)
                sens_apis = app.checkSensitiveAPIs()

                if sens_apis:
                    logger.info(f"🔥 Agreement Gate triggered {len(sens_apis)} APIs!")
                    app.all_sensitive_api_list.extend(sens_apis)

                if sens_apis and collect_pre_consent:

                    os.makedirs('dumps/' + app.appPackage, exist_ok=True)
                    dir_time = datetime.now().strftime("%Y%m%d%H%M%S")
                    dir_time_path = f"dumps/{app.appPackage}/{dir_time}_AGREE_{i}"
                    os.makedirs(dir_time_path, exist_ok=True)

                    new_xml = app.dm.dump_hierarchy(compressed=False)
                    new_gui = app.dm.screenshot()

                    save_gui_image(path=dir_time_path, img_dict={'old_gui': old_gui, 'new_gui': new_gui}, quality=30,
                                   scale=0.3)
                    save_xml_file(path=dir_time_path, xml_dict={'old_xml': old_xml, 'new_xml': new_xml})
                    save_json_file(path=dir_time_path, json_dict={
                        "pre_click_apis": pre_click_apis,
                        'api_name_list': sens_apis,
                        'stage': 'agreement_gate',
                        'click_point': agree_widget
                    })

                try:
                    if not app.refreshNewObservation():
                        logger.warning("Gate handler failed to refresh observation, exiting gate loop.")
                        break
                except RuntimeError as e:
                    logger.error(f"Gate Handler: Refresh 失败，App 疑似崩溃，向上抛出异常: {e}")
                    raise  # 重新抛出，跳出 explore3.py 的大循环
            else:
                logger.debug(f"第 {i + 1} 层：未检测到同意/引导组件，退出 Gate 循环。")
                break
        except RuntimeError:
            raise  # 保持向上抛出，终止 APK 任务

        except Exception as e:
            logger.warning(f"Error in handle_agreement_gate (Non-fatal): {type(e).__name__}: {e}")
        try:
            app.refreshNewObservation()
        except:
            raise  # 刷新都失败了，彻底退出
        break  # 发生非致命错误，退出 Gate 循环
    logger.info("Agreement Gate handling finished.")  # <-- ✅ 修正后的位置


def record_status(app_name, status, reason=""):
    """
    记录 APK 处理状态
    status: 'success' 或 'failed'
    """
    filename = "processed_success.txt" if status == "success" else "processed_failed.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a", encoding="utf-8") as f:
        if status == "success":
            f.write(f"[{timestamp}] {app_name}\n")
        else:
            f.write(f"[{timestamp}] {app_name} | Reason: {reason}\n")


def reset_infrastructure(device_ip):
    logger.warning("♻️ 正在执行基础设施深度重置 (ADB/Uiautomator2/Frida)...")
    try:
        subprocess.run(f"adb -s {device_ip} shell pkill atx-agent", shell=True)
        subprocess.run(f"adb -s {device_ip} shell pkill uiautomator", shell=True)
        subprocess.run(f"adb -s {device_ip} shell pkill frida-server", shell=True)

        if ":" in device_ip:
            subprocess.run(f"adb disconnect {device_ip}", shell=True)
            time.sleep(1)
            subprocess.run(f"adb connect {device_ip}", shell=True)
            time.sleep(2)
        from utils.driver_manager import driver_manager
        driver_manager.init(device_ip, auto_restart_uia=True)
        driver_manager._driver.reset_uiautomator()

        logger.info("✅ 基础设施重置完成")
    except Exception as e:
        logger.error(f"❌ 重置基础设施失败: {e}")


if __name__ == '__main__':
    main()
