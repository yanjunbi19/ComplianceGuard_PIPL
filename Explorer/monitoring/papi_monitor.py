# monitoring/papi_monitor.py
import sys
import os
import traceback
import os
import sys
current_file_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_file_path))
if project_root not in sys.path:
    sys.path.append(project_root)
import time
import base64

from Explorer.utils.static_analysis import analyze_apk_for_hooks


from Explorer.utils.monitoring_utils import *

import frida
import json
from datetime import datetime
import argparse
from rich import print
from rich.console import Console
from loguru import logger
import json

from argparse import Namespace
import config
import traceback
JS_DIR = os.path.dirname(os.path.abspath(__file__))
MASTER_JS_PATH = os.path.join(JS_DIR, "un4.js")


HOOKS_DIR = "G:\iie\mylab\guitest\Explorer\hooks"

# ========== 全局变量 ==========
CURRENT_APP_OUTPUT_DIR = None
PERMISSION_LOG_FILE = None
crypto_hooks_set = set()
permission_hooks_set = set()

def register_hooks(permission_hooks, crypto_hooks):
    """注册 hooks 签名，用于 on_message 过滤"""
    global permission_hooks_set, crypto_hooks_set

    permission_hooks_set.clear()
    crypto_hooks_set.clear()

    # 注册权限 API
    for class_name, method_name in permission_hooks:
        signature = f"{class_name}.{method_name}"
        permission_hooks_set.add(signature)

    # 注册加密函数
    for class_name, method_name in crypto_hooks:
        signature = f"{class_name}.{method_name}"
        crypto_hooks_set.add(signature)


def on_message(message, data=None):
    """
    处理来自 Master 脚本的所有消息，并精准分发到对应文件。
    适配 Python 隐私分析脚本。
    """
    global CURRENT_APP_OUTPUT_DIR
    if not CURRENT_APP_OUTPUT_DIR:
        print("ERROR: CURRENT_APP_OUTPUT_DIR is NONE!")
        return

    try:
        if message.get('type') == 'send':
            payload = message.get('payload')

            # 1. 如果 payload 是字符串（通常是加密模块发出的 JSON 字符串）
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except:
                    pass  # 保持原样

            if not isinstance(payload, dict): return

            # 确定当前阶段后缀 (-1 或 -2)
            stage_suffix = "-2" if os.path.exists(os.path.join(CURRENT_APP_OUTPUT_DIR, "2nd.lock")) else "-1"

            # ========== 核心分发逻辑 ==========

            # 1️⃣ 隐私 API 调用 (进入 permission-X.txt)
            # 特征：包含 'class' 和 'method'
            if payload.get('category') == "CryptoAPI" or 'crypto' in payload:
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"crypt{stage_suffix}.txt")

                with open(output_file, 'a', encoding='utf-8') as f:
                    # 我们直接保存整个 payload，这样 class, method, args(Base64) 都在里面
                    json.dump(payload, f, ensure_ascii=False)
                    f.write('\n')
                return  # 处理完毕，直接返回

                # 2️⃣ 隐私 API 调用 (进入 permission-X.txt)
                # 现在只有非加密类的隐私 API 会走到这里
            if 'class' in payload and 'method' in payload:
                api_sig = f"{payload['class']}.{payload['method']}"
                # 存入全局变量供 RL 环境给奖励
                config.api_trigged_list.add(api_sig)

                # 原有的写入文件逻辑保持不变
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"permission{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(payload, f, ensure_ascii=False)
                    f.write('\n')
                return
            # 3️⃣ 网络连接数据 (进入 java_network-X.txt 或 native_network-X.txt)
            if 'java' in payload:
                java_data = payload['java'] # 👈 取出内层
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"java_network{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(java_data, f, ensure_ascii=False)
                    f.write('\n')
                return

            if 'native' in payload:
                native_data=payload['native']
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"native_network{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(native_data, f, ensure_ascii=False)
                    f.write('\n')
                return
            if 'media' in payload:
                media_data = payload['media']
                # 触发 RL 奖励（媒体调用通常也是敏感行为）
                api_sig = f"{media_data['class']}.{media_data['method']}"
                #config.api_trigged_list.add(api_sig)
                
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"media{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(media_data, f, ensure_ascii=False)
                    f.write('\n')
                logger.info(f"📸 [Media Event] {api_sig} recorded.")
                return
            # 4️⃣ 文件系统操作 (进入 fs-X.txt)
            if 'fs' in payload:
                # 👈 核心修复：取出内层数据
                fs_data = payload['fs']

                # 🛡️ 确保 fs_data 是字典且包含 function 键
                if isinstance(fs_data, dict) and 'function' in fs_data:
                    output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"fs{stage_suffix}.txt")
                    with open(output_file, 'a', encoding='utf-8') as f:
                        # ✅ 只保存 fs_data，这样每一行就是 {"function": "...", ...}
                        json.dump(fs_data, f, ensure_ascii=False)
                        f.write('\n')
                return

            # 5️⃣ 设备标识符 (进入 id-X.txt)
            if 'deviceid' in payload:
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"id{stage_suffix}.txt")
                record = {
                    "ts": datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
                    "android_id": payload['deviceid']
                }
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(record, f, ensure_ascii=False)
                    f.write('\n')
                return
            if 'hookerror' in payload:
                hook_err = payload['hookerror']
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"hookerror{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(hook_err, f, ensure_ascii=False)
                    f.write('\n')
                logger.warning(
                    f"🧩 HookError [{hook_err.get('stage')}]: {hook_err.get('error', hook_err)}"
                )
                return

            if 'hookstat' in payload:
                hook_data = payload['hookstat']
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"hookstat{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(hook_data, f, ensure_ascii=False)
                    f.write('\n')
                logger.info(
                    f"🪝 Hook统计: categories={hook_data.get('requestedCategories')} "
                    f"requestedMethods={hook_data.get('requestedMethods')} "
                    f"hookedMethods={hook_data.get('hookedMethods')} "
                    f"hookedOverloads={hook_data.get('hookedOverloads')} "
                    f"failed={hook_data.get('failedCount')}"
                )
                return
            if 'diag' in payload:
                diag_data = payload['diag']
                output_file = os.path.join(CURRENT_APP_OUTPUT_DIR, f"diag{stage_suffix}.txt")
                with open(output_file, 'a', encoding='utf-8') as f:
                    json.dump(diag_data, f, ensure_ascii=False)
                    f.write('\n')
                logger.warning(f"🛠 DIAG: {diag_data.get('type')} -> {diag_data}")
                return
        elif message.get('type') == 'error':
            # ✨ 改进：如果 stack 是 None，就打印 description
            error_details = message.get('stack') or message.get('description') or "Unknown Error"
            logger.error(f"❌ [FRIDA ERROR] {error_details}")

    except Exception as e:
        logger.error(f"❌ [ON_MESSAGE HANDLER ERROR] {e}")


def init_crypto_logging(app_name, algo="sac", stage=1):  # 增加 algo 参数
    global CURRENT_APP_OUTPUT_DIR
    # ✨ 强制使用绝对路径，防止线程间路径不一致
    base_path = os.path.abspath("analysis")

    # 修改路径逻辑：analysis/[algo]/[app_name]
    CURRENT_APP_OUTPUT_DIR = os.path.join(base_path, algo, app_name)

    os.makedirs(CURRENT_APP_OUTPUT_DIR, exist_ok=True)
    logger.info(f"📂 [Monitor] 算法: {algo} | 绝对输出路径已初始化: {CURRENT_APP_OUTPUT_DIR}")



def main_v2(package_name, all_hooks_list, stage=1):
    import frida
    import time
    import threading

    session = None
    script = None

    retry_count = 0
    max_retries = 1
    min_survival_time = 10

    if package_name not in config.app_first_run_done:
        config.app_first_run_done[package_name] = False

    logger.info(f"🚀 Frida 监控守护启动: {package_name}")

    backoff = 1.0
    backoff_max = 12.0

    while config.thread_life:
        start_time = time.time()
        detached_evt = threading.Event()
        detached_reason = {"reason": None}

        try:
            if retry_count >= max_retries:
                logger.error(f"❌ App {package_name} 连续崩溃或断开次数过多 ({retry_count})，监控线程停止。")
                break

            try:
                device = frida.get_usb_device(timeout=3)
            except Exception:
                logger.warning("等待 Frida 设备重连...")
                time.sleep(min(backoff, backoff_max))
                backoff = min(backoff * 1.6, backoff_max)
                continue

            should_spawn = not config.app_first_run_done[package_name]
            pid = -1
            did_spawn = False

            if should_spawn:
                logger.info(f"未检测到进程，正在 Spawn {package_name}... (首次/强制启动)")
                pid = device.spawn([package_name])
                session = device.attach(pid)
                did_spawn = True
                retry_count = 0
            else:
                try:
                    pid = device.get_process(package_name).pid
                    logger.info(f"检测到 {package_name} (PID: {pid}) 已运行，尝试 Attach...")
                    session = device.attach(pid)
                    retry_count = 0
                except frida.ProcessNotFoundError:
                    logger.warning(f"进程 {package_name} 未运行，等待主线程拉起... (重试 {retry_count + 1})")
                    time.sleep(3)
                    retry_count += 1
                    continue

            def _on_detached(reason, crash):
                detached_reason["reason"] = str(reason)
                config.frida_ready = False
                detached_evt.set()

            session.on("detached", _on_detached)

            with open(MASTER_JS_PATH, 'r', encoding='utf-8') as f:
                frida_code = f.read()

            script = session.create_script(frida_code)
            script.on("message", on_message)
            script.load()

            privacy_hooks = [{"clazz": h[0], "method": h[1]} for h in all_hooks_list
                             if h[0].startswith(("android.", "com.android.", "java.lang."))]
            crypto_hooks = [{"clazz": h[0], "method": h[1]} for h in all_hooks_list
                            if not h[0].startswith(("android.", "com.android.", "java.lang."))]

            api_data_list = [
                {"Category": "PrivacyAPI", "hooks": privacy_hooks},
                {"Category": "CryptoAPI", "hooks": crypto_hooks}
            ]

            try:
                config.frida_ready = False
                script.exports.apimonitor(api_data_list)
                logger.info(f"✅ Hooks 注入成功 (隐私:{len(privacy_hooks)} 加密:{len(crypto_hooks)})")
                config.frida_ready = True
                backoff = 1.0  # 成功后重置退避

                if should_spawn:
                    config.app_first_run_done[package_name] = True

            except Exception as e:
                logger.error(f"RPC 注入 Hooks 失败: {e}")
                retry_count += 1
                try:
                    session.detach()
                except:
                    pass
                continue

            if did_spawn:
                try:
                    device.resume(pid)
                except:
                    pass

            logger.info("📡 进入稳定监控阶段...")
            # 等待 detached；留一个超时用于周期性检查 thread_life
            while config.thread_life and not detached_evt.wait(timeout=2.0):
                pass

            if not config.thread_life:
                break

            survival_duration = time.time() - start_time
            logger.error(f"🚨 Frida Session 已断开 (存活时长: {survival_duration:.1f}s, reason={detached_reason['reason']})")

            if survival_duration < min_survival_time:
                retry_count += 1
                logger.warning(f"⚠️ App 疑似启动即崩溃，错误计数: {retry_count}/{max_retries}")
                logger.warning("🔨 快速断开，下一次重试强制使用 Spawn 模式。")
                config.app_first_run_done[package_name] = False
            else:
                retry_count = 0

            config.frida_ready = False

            time.sleep(min(backoff, backoff_max))
            backoff = min(backoff * 1.6, backoff_max)

        except Exception as e:
            logger.error(f"⚠️ Frida 运行异常: {e}")
            retry_count += 1
            time.sleep(min(backoff, backoff_max))
            backoff = min(backoff * 1.6, backoff_max)

        finally:
            try:
                if script:
                    script.unload()
                if session:
                    session.detach()
            except:
                pass
            session = None
            script = None

    logger.info("🛑 Frida 监控线程已完全退出")



def load_hooks_from_cache(package_name):
    """从 hooks/{package}.json 加载预生成的 hook 规则（加密函数）"""
    cache_path = os.path.join(HOOKS_DIR, f"{package_name}.json")
    converted_api_list = []

    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                raw_data_from_json = json.load(f)

            if isinstance(raw_data_from_json, list):
                for hook_structure_dict in raw_data_from_json:
                    if isinstance(hook_structure_dict, dict) and 'hooks' in hook_structure_dict:
                        for hook_item in hook_structure_dict['hooks']:
                            if isinstance(hook_item, dict) and 'clazz' in hook_item and 'method' in hook_item:
                                converted_api_list.append((hook_item['clazz'], hook_item['method']))

                logger.info(f"✅ Loaded {len(converted_api_list)} crypto hooks from cache: {cache_path}")

            elif isinstance(raw_data_from_json, dict) and 'hooks' in raw_data_from_json:
                for hook_item in raw_data_from_json['hooks']:
                    if isinstance(hook_item, dict) and 'clazz' in hook_item and 'method' in hook_item:
                        converted_api_list.append((hook_item['clazz'], hook_item['method']))

                logger.info(f"✅ Loaded {len(converted_api_list)} crypto hooks from cache")

        except Exception as e:
            logger.warning(f"⚠️ Failed to load cache: {e}")
    else:
        logger.warning(f"🔍 No cache found for {package_name}")

    return converted_api_list

def start_monitoring(package_name, stage, algo="sac"):
    """外部调用入口"""
    init_crypto_logging(package_name, algo=algo, stage=stage)

    # 1. 从缓存加载自动发现的 hooks（加密函数）
    # logger.debug(f"Config ID: {id(config)}, thread_life: {config.thread_life}")
    crypto_hooks = load_hooks_from_cache(package_name)

    # 2. 加载手动配置（权限 API）
    list_file_api_to_monitoring = ['permissions_api.txt']
    permission_hooks = create_list_api_from_file(list_file_api_to_monitoring)
    logger.info(f"🔐 Loaded {len(permission_hooks)} permission hooks from file.")

    # 注册 hooks
    register_hooks(permission_hooks, crypto_hooks)

    # 3. 合并所有 hooks
    all_hooks = permission_hooks + crypto_hooks

    logger.info(f"🎯 Deploying {len(permission_hooks_set) + len(crypto_hooks_set)} unique hooks:")
    logger.info(f"   - Permission APIs: {len(permission_hooks_set)}")
    logger.info(f"   - Crypto Functions: {len(crypto_hooks_set)}")


    main_v2(package_name, all_hooks, stage=stage)

if __name__ == "__main__":
    config.thread_life = True

    start_monitoring('com.ganji.android.haoche_c', stage=1)
