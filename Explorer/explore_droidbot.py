# -*- coding: utf-8 -*-
import os
import re
import gc
import sys
import json
import time
import shutil
import pickle
import random
import argparse
import traceback
import subprocess
import numpy as np

from pathlib import Path
from datetime import datetime
from threading import Thread
from loguru import logger

import config
from utils import apk_util
from utils.general_util import scan_file
from utils.screen_util import save_json_file
from utils.network import Monitor
from monitoring import papi_monitor1
from utils.adbHelper import checkPackageInstall
from utils.monitoring_utils import install_frida

import os
os.environ["PYTHONIOENCODING"] = "utf-8"
ADB_DEVICE = config.ADB_DEVICE

script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

seed = 1234
random.seed(seed)
np.random.seed(seed)
FRIDA_REMOTE_ADDR = "127.0.0.1:27042"
FRIDA_PORT = 27042

# ==========================================================
# 异常定义
# ==========================================================
class FridaMonitorDiedError(RuntimeError):
    pass


class DroidBotTimeoutError(TimeoutError):
    pass


# ==========================================================
# 通用工具
# ==========================================================
def normalize_activity_name(act, appPackage=None):
    if not act:
        return None
    act = str(act).strip()

    if "/" in act:
        pkg, activity = act.split("/", 1)
        if activity.startswith("."):
            return pkg + activity
        return activity

    if act.startswith(".") and appPackage:
        return appPackage + act

    return act


def record_status(app_name, status, reason="", success_file="processed_success.txt", failed_file="processed_failed.txt"):
    filename = success_file if status == "success" else failed_file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a", encoding="utf-8") as f:
        if status == "success":
            f.write(f"[{timestamp}] {app_name}\n")
        else:
            f.write(f"[{timestamp}] {app_name} | Reason: {reason}\n")


# ==========================================================
# ADB Helper
# ==========================================================
_ACTIVITY_RE = re.compile(r'([A-Za-z0-9._]+)/(\.?[A-Za-z0-9_$.\-]+)')

_SYSTEM_PKG_KEYWORDS = (
    "inputmethod",
    "keyboard",
    "ime",
    "systemui",
    "launcher",
    "permissioncontroller",
    "packageinstaller",
)


def adb_run(args, timeout=15, check=False):
    cmd = ["adb", "-s", ADB_DEVICE] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"ADB command failed: {' '.join(cmd)}\n"
            f"stdout={result.stdout}\n"
            f"stderr={result.stderr}"
        )
    return result


def adb_shell(cmd, timeout=15, check=False):
    return adb_run(["shell", "sh", "-c", cmd], timeout=timeout, check=check)


def adb_connect(device_ip):
    if not device_ip or device_ip.startswith("emulator-") or ":" not in device_ip:
        logger.info(f"🔌 [ADB] 使用现有设备 serial: {device_ip}")
        return True

    logger.info(f"🔌 [ADB] 确保设备连接: {device_ip}")
    try:
        result = subprocess.run(
            ["adb", "connect", device_ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10
        )
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        logger.info(f"🔌 [ADB] connect output: {output}")
        return True
    except Exception as e:
        logger.warning(f"⚠️ [ADB] connect failed: {e}")
        return False


def adb_force_stop(package_name):
    try:
        adb_run(["shell", "am", "force-stop", package_name], timeout=10)
        logger.info(f"🛑 [ADB] force-stop: {package_name}")
        return True
    except Exception as e:
        logger.warning(f"⚠️ [ADB] force-stop failed: {package_name}, error={e}")
        return False


def adb_pm_clear(package_name):
    try:
        result = adb_run(["shell", "pm", "clear", package_name], timeout=20)
        logger.info(f"🧹 [ADB] pm clear: {package_name}")
        logger.debug((result.stdout or "").strip())
        return True
    except Exception as e:
        logger.warning(f"⚠️ [ADB] pm clear failed: {package_name}, error={e}")
        return False


def build_component_name(package_name, activity_name=None):
    if not activity_name:
        return None

    act = str(activity_name).strip()

    if "/" in act:
        return act
    if act.startswith("."):
        return f"{package_name}/{act}"
    if act.startswith(package_name):
        return f"{package_name}/{act}"
    return f"{package_name}/{act}"


def adb_start_app(package_name, activity_name=None):
    component = build_component_name(package_name, activity_name)
    start_ok = False

    try:
        if component:
            result = adb_run(["shell", "am", "start", "-W", "-n", component], timeout=25)
            out = (result.stdout or "").strip()
            logger.info(f"🚀 [ADB] start app via am start: {component}")
            logger.debug(out)

            ok_keys = ["Status: ok", "Complete", "Warning: Activity not started"]
            if any(k in out for k in ok_keys):
                start_ok = True
        else:
            result = adb_run(
                ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                timeout=25
            )
            out = (result.stdout or "").strip()
            logger.info(f"🚀 [ADB] start app via monkey: {package_name}")
            logger.debug(out)
            if "Events injected" in out or result.returncode == 0:
                start_ok = True

        if start_ok:
            return True
    except Exception as e:
        logger.warning(f"⚠️ [ADB] app start failed: {package_name}, error={e}")

    try:
        result = adb_run(
            ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=25
        )
        out = (result.stdout or "").strip()
        logger.info(f"🚀 [ADB] fallback monkey start: {package_name}")
        logger.debug(out)
        return ("Events injected" in out) or (result.returncode == 0)
    except Exception as e:
        logger.warning(f"⚠️ [ADB] fallback monkey start failed: {package_name}, error={e}")
        return False


def _is_noise_package(pkg: str, target_pkg: str = None):
    if not pkg:
        return True

    p = pkg.lower().strip()

    if target_pkg and p == target_pkg.lower():
        return False

    if p in ("keyb",):
        return True

    return any(k in p for k in _SYSTEM_PKG_KEYWORDS)


def _extract_activity_candidates(text):
    candidates = []
    lines = text.splitlines()

    for line in lines:
        m = _ACTIVITY_RE.search(line)
        if m:
            pkg, act = m.group(1), m.group(2)
            candidates.append({
                "package": pkg.strip(),
                "activity": normalize_activity_name(f"{pkg}/{act}", pkg)
            })

    return candidates


def adb_get_top_app(target_pkg=None):
    cmd_list = [
        ["shell", "dumpsys", "activity", "top"],
        ["shell", "dumpsys", "activity", "activities"],
        ["shell", "dumpsys", "window", "windows"],
    ]

    priority_keys = [
        "topResumedActivity",
        "mResumedActivity",
        "ResumedActivity",
        "mFocusedApp",
        "mCurrentFocus",
        "topActivity",
    ]

    for cmd in cmd_list:
        try:
            result = adb_run(cmd, timeout=15)
            text = (result.stdout or "") + "\n" + (result.stderr or "")
            lines = text.splitlines()

            priority_hits = []
            for key in priority_keys:
                for line in lines:
                    if key in line:
                        m = _ACTIVITY_RE.search(line)
                        if m:
                            pkg, act = m.group(1), m.group(2)
                            priority_hits.append({
                                "package": pkg.strip(),
                                "activity": normalize_activity_name(f"{pkg}/{act}", pkg)
                            })

            for item in priority_hits:
                if target_pkg and item["package"] == target_pkg:
                    return item

            for item in priority_hits:
                if not _is_noise_package(item["package"], target_pkg):
                    return item

            candidates = _extract_activity_candidates(text)

            for item in candidates:
                if target_pkg and item["package"] == target_pkg:
                    return item

            for item in candidates:
                if not _is_noise_package(item["package"], target_pkg):
                    return item

        except Exception as e:
            logger.debug(f"[ADB] get top app failed on {' '.join(cmd)}: {e}")

    return {"package": "", "activity": ""}


def adb_get_top_package(target_pkg=None):
    return adb_get_top_app(target_pkg=target_pkg).get("package", "")


def adb_pidof(package_name):
    try:
        result = adb_run(["shell", "pidof", package_name], timeout=8)
        pid_text = (result.stdout or "").strip()
        return pid_text if pid_text else ""
    except Exception:
        return ""


def adb_ensure_app_running(package_name, activity_name=None, wait_timeout=20):
    cur_info = adb_get_top_app(target_pkg=package_name)
    cur = cur_info.get("package", "")

    if cur == package_name:
        logger.debug(f"✅ [ADB] App {package_name} 已在前台")
        return True

    logger.warning(f"⚠️ [ADB] App 不在前台(当前: {cur or 'unknown'})，尝试启动 {package_name}")
    start_ok = adb_start_app(package_name, activity_name)

    start = time.time()
    while time.time() - start < wait_timeout:
        cur_info = adb_get_top_app(target_pkg=package_name)
        cur = cur_info.get("package", "")

        if cur == package_name:
            logger.info(f"✅ [ADB] App {package_name} 已启动到前台")
            return True

        pid_text = adb_pidof(package_name)
        if pid_text:
            logger.info(f"✅ [ADB] 检测到 {package_name} 进程存在(pid={pid_text})，继续执行")
            return True

        time.sleep(1)

    pid_text = adb_pidof(package_name)
    if pid_text:
        logger.warning(
            f"⚠️ [ADB] 未稳定检测到前台包，但 {package_name} 进程已存在(pid={pid_text})，继续执行"
        )
        return True

    if start_ok:
        logger.warning(
            f"⚠️ [ADB] am start 已执行成功，但前台检测仍不稳定，可能被输入法/系统窗口干扰，继续执行"
        )
        return True

    logger.warning(f"⚠️ [ADB] 未确认 {package_name} 进入前台")
    return False


def adb_remove_forward_by_remote_ports(remote_ports=(7912, 7336)):
    try:
        result = adb_run(["forward", "--list"], timeout=10)
        lines = (result.stdout or "").splitlines()
        targets = {f"tcp:{p}" for p in remote_ports}

        for line in lines:
            parts = line.strip().split()
            if len(parts) != 3:
                continue

            serial, local, remote = parts
            if serial == ADB_DEVICE and remote in targets:
                adb_run(["forward", "--remove", local], timeout=10)
                logger.info(f"🧹 [ADB] removed forward: {local} -> {remote}")
    except Exception as e:
        logger.warning(f"⚠️ [ADB] remove forward failed: {e}")


def adb_kill_infra_processes(kill_frida=True, kill_uia=True, kill_atx=True):
    cmds = []

    if kill_frida:
        cmds.extend([
            "pkill -9 frida-server >/dev/null 2>&1 || true",
            "pkill -9 frida >/dev/null 2>&1 || true",
        ])
    if kill_uia:
        cmds.extend([
            "pkill -9 uiautomator >/dev/null 2>&1 || true",
            "pkill -9 com.github.uiautomator >/dev/null 2>&1 || true",
        ])
    if kill_atx:
        cmds.extend([
            "pkill -9 atx-agent >/dev/null 2>&1 || true",
        ])

    if not cmds:
        return

    try:
        adb_shell(" ; ".join(cmds), timeout=10)
        logger.info("🧹 [ADB] 基础设施残留进程清理完成")
    except Exception as e:
        logger.warning(f"⚠️ [ADB] 清理基础设施残留失败: {e}")


def adb_cleanup_uiautomator_residue():
    logger.info("🧹 [ADB] 清理 uiautomator/atx-agent/forward 残留...")

    for pkg in [
        "com.github.uiautomator",
        "com.github.uiautomator.test",
        "io.appium.uiautomator2.server",
        "io.appium.uiautomator2.server.test",
    ]:
        try:
            adb_run(["shell", "am", "force-stop", pkg], timeout=8)
        except Exception:
            pass

    for cmd in [
        "pkill -f uiautomator >/dev/null 2>&1 || true",
        "pkill -f atx-agent >/dev/null 2>&1 || true",
        "pkill -f com.github.uiautomator >/dev/null 2>&1 || true",
    ]:
        try:
            adb_shell(cmd, timeout=8)
        except Exception:
            pass

    adb_remove_forward_by_remote_ports(remote_ports=(7912, 7336))
    time.sleep(1.5)
    logger.info("✅ [ADB] 冲突残留清理完成")


# ==========================================================
# DroidBot 专用 Frida 上下文
# ==========================================================
class DroidBotFridaContext:
    """
    仅用于 DroidBot 模式：
    - 不依赖 RLApplicationEnv
    - 不依赖 driver_manager
    - 只负责 Frida API 监控上下文
    """
    def __init__(self, appPackage, appActivity, application, stage, algo="droidbot"):
        self.appPackage = appPackage
        self.appActivity = appActivity
        self.application = application
        self.stage = stage
        self.algo = algo

        self.monitoring_thread = None
        self.all_sensitive_api_list = []
        self.app_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def checkSensitiveAPIs(self):
        sense_api_trigged_list = list(config.api_trigged_list)
        if len(sense_api_trigged_list) > 0:
            config.api_trigged_list.clear()
        return sense_api_trigged_list


def init_droidbot_frida_context(application, appPackage, appActivity, stage, warmup_sec=12):
    logger.info("🧩 [DroidBot] 初始化独立 Frida 上下文...")

    ctx = DroidBotFridaContext(
        appPackage=appPackage,
        appActivity=appActivity,
        application=application,
        stage=stage,
        algo="droidbot"
    )

    if stage == 1:
        logger.info("🛠️ [DroidBot] 阶段 1：准备 Frida")
        install_frida(application, appPackage, appActivity)
    else:
        logger.info("⏩ [DroidBot] 阶段 2：检查 App 是否存在并准备 Frida")
        install_frida(application, appPackage, appActivity)
        if not checkPackageInstall(appPackage):
            raise RuntimeError(f"❌ 阶段 2 失败：应用 {appPackage} 未安装")

    logger.info("⏳ [DroidBot] 不主动启动目标 App，等待 DroidBot 接管生命周期...")
    subprocess.run(
        ["adb", "-s", ADB_DEVICE, "forward", "tcp:27042", "tcp:27042"],
        capture_output=True, timeout=10
    )
    FRIDA_REMOTE_ADDR = "127.0.0.1:27042"

    ctx.monitoring_thread = Thread(
        target=papi_monitor1.start_monitoring,
        args=(appPackage, stage, "droidbot"),
        kwargs={
            "attach_only": True,
            "device_serial": ADB_DEVICE,  # 可保留
            "remote_addr": FRIDA_REMOTE_ADDR  # 新增
        },
        daemon=True
    )
    ctx.monitoring_thread.start()

    logger.info("⏳ [DroidBot] attach-only 模式下仅等待监控线程启动，不等待目标进程/Hook 就绪...")
    boot_wait_sec = 2
    for _ in range(boot_wait_sec):
        if not ctx.monitoring_thread.is_alive():
            raise RuntimeError("Frida monitoring thread died during DroidBot init.")
        time.sleep(1)
    logger.info("✅ [DroidBot] Frida 守护线程已启动，立即交由 DroidBot 拉起 App")
    return ctx


def stop_droidbot_frida_context(ctx):
    if ctx is None:
        return

    try:
        config.thread_life = False
    except Exception:
        pass

    try:
        if hasattr(ctx, "monitoring_thread") and ctx.monitoring_thread and ctx.monitoring_thread.is_alive():
            ctx.monitoring_thread.join(timeout=3)
    except Exception as e:
        logger.warning(f"stop_droidbot_frida_context join failed: {e}")


# ==========================================================
# 敏感 API 数据处理
# ==========================================================
def flush_sensitive_apis(app, tag="runtime", save_dump=False):
    if app is None:
        return []

    try:
        sens_apis = app.checkSensitiveAPIs()
        if sens_apis:
            logger.warning(f"🚩 [{tag}] 捕获到 {len(sens_apis)} 个敏感 API: {sens_apis}")
            if not hasattr(app, "all_sensitive_api_list"):
                app.all_sensitive_api_list = []
            app.all_sensitive_api_list.extend(sens_apis)

            if save_dump:
                os.makedirs(f'dumps/{app.appPackage}', exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                save_path = f"dumps/{app.appPackage}/{timestamp}_{tag}"
                os.makedirs(save_path, exist_ok=True)
                save_json_file(path=save_path, json_dict={
                    "api_name_list": sens_apis,
                    "stage": tag
                })
        return sens_apis
    except Exception as e:
        logger.warning(f"flush_sensitive_apis failed at [{tag}]: {e}")
        return []


def persist_sensitive_api_records(app, app_name, algo="droidbot"):
    try:
        api_trigger_dir = os.path.join('apiTrigger', algo)
        os.makedirs(api_trigger_dir, exist_ok=True)

        api_list = []
        if app is not None and hasattr(app, "all_sensitive_api_list"):
            api_list = app.all_sensitive_api_list

        with open(os.path.join(api_trigger_dir, f"{app_name}_api_trigger.pkl"), 'wb') as f:
            pickle.dump(api_list, f)

        logger.info(f"💾 已保存敏感 API 记录: {app_name}, count={len(api_list)}")
    except Exception as e:
        logger.warning(f"保存敏感 API 记录失败: {e}")


# ==========================================================
# DroidBot 执行与覆盖率统计
# ==========================================================
def run_droidbot_exploration(application, appPackage, app_name, output_dir, args, app=None):
    droidbot_out = os.path.abspath(os.path.join(output_dir, args.droidbot_output_subdir))
    application = os.path.abspath(application)

    if os.path.exists(droidbot_out):
        shutil.rmtree(droidbot_out, ignore_errors=True)
    os.makedirs(droidbot_out, exist_ok=True)

    log_path = os.path.join(droidbot_out, "droidbot_stdout.log")

    cmd = [
        sys.executable, "-m", "droidbot.start",
        "-d", ADB_DEVICE,
        "-a", application,
        "-policy", args.droidbot_policy,
        "-count", str(args.droidbot_count),
        "-interval", str(args.droidbot_interval),
        "-timeout", str(args.droidbot_timeout),
        "-o", droidbot_out,
        "-keep_env",
        "-keep_app",
        "-grant_perm"
    ]

    if args.droidbot_is_emulator:
        cmd.append("-is_emulator")

    logger.info("🤖 DroidBot command: " + " ".join(cmd))
    logger.info(f"📄 DroidBot log file: {log_path}")

    start_ts = time.time()
    last_flush_ts = 0

    with open(log_path, "w", encoding="utf-8", buffering=1) as log_file:
        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=script_dir
        )

        try:
            while True:
                if process.poll() is not None:
                    break

                try:
                    check_frida_health_or_raise(app, appPackage, frida_grace_sec=60)
                except FridaMonitorDiedError as e:
                    logger.warning(f"⚠️ DroidBot 运行期间 Frida 异常，但不中断探索。reason={e}")

                now = time.time()

                if now - last_flush_ts >= 5:
                    flush_sensitive_apis(app, tag="DROIDBOT_RUNTIME", save_dump=True)
                    last_flush_ts = now

                if now - start_ts > args.droidbot_timeout + 180:
                    logger.error("⏰ DroidBot 超时，强制终止。")
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except Exception:
                        process.kill()
                    raise DroidBotTimeoutError("DroidBot process timeout.")

                time.sleep(2)

            ret = process.wait()

        except Exception:
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=10)
                except Exception:
                    process.kill()
            raise

    if ret != 0:
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                tail = f.readlines()[-50:]
            logger.error("❌ DroidBot 最后日志:\n" + "".join(tail))
        except Exception:
            logger.error("❌ DroidBot 失败，且读取日志尾部失败。")
        raise RuntimeError(f"DroidBot failed with return code {ret}")

    logger.info(f"✅ DroidBot 探索完成: {app_name}")
    return droidbot_out


def collect_droidbot_coverage(droidbot_out, all_activities_list, appPackage):
    visited = set()
    total_activities = set()

    for a in all_activities_list:
        na = normalize_activity_name(a, appPackage)
        if na:
            total_activities.add(na)

    for state_file in Path(droidbot_out).rglob("state*.json"):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            act = data.get("foreground_activity") or data.get("activity")
            act = normalize_activity_name(act, appPackage)
            if act:
                visited.add(act)
        except Exception as e:
            logger.warning(f"解析 DroidBot state 文件失败: {state_file}, error={e}")

    matched = visited & total_activities
    coverage_rate = len(matched) / len(total_activities) if total_activities else 0.0
    return coverage_rate, matched, visited

def check_frida_health_or_raise(app, package_name, frida_grace_sec=40):
    if app is None:
        return

    # 1. 线程死了，直接报错
    if hasattr(app, "monitoring_thread") and app.monitoring_thread and (not app.monitoring_thread.is_alive()):
        reason = getattr(config, "frida_last_error", "") or "FridaMonitorThreadDead"
        raise FridaMonitorDiedError(reason)

    # 2. 明确硬失败
    if getattr(config, "frida_hard_failed", False):
        reason = getattr(config, "frida_last_error", "") or "FridaHardFailed"
        raise FridaMonitorDiedError(reason)

    # 3. attach-only 模式下，不要仅凭 pidof 就判死
    top_info = adb_get_top_app(target_pkg=package_name)
    top_pkg = top_info.get("package", "")
    pid_text = adb_pidof(package_name)

    # 只有当前台已经是目标包时，才要求 frida_ready
    if top_pkg == package_name:
        if not getattr(config, "frida_ready", False):
            first_seen_ts = getattr(config, "frida_target_top_seen_ts", 0.0) or 0.0
            now = time.time()

            if first_seen_ts <= 0:
                config.frida_target_top_seen_ts = now
            elif now - first_seen_ts > frida_grace_sec:
                reason = getattr(config, "frida_last_error", "") or \
                         f"FridaNotReadyFor{frida_grace_sec}sAfterTopAppVisible"
                raise FridaMonitorDiedError(reason)
    else:
        # 前台不是目标包，先别判死
        config.frida_target_top_seen_ts = 0.0

# ==========================================================
# Main
# ==========================================================
def main():
    parser = argparse.ArgumentParser(description='Standalone DroidBot explorer with Frida monitoring')
    parser.add_argument('--apps', type=str, default='apps/testapp')
    parser.add_argument('--apps_explored', type=str, default='apps/testapp_end')
    parser.add_argument('--stage', type=int, default=2, help='1: Unlogged stage, 2: Logged stage')

    parser.add_argument('--droidbot_policy', type=str, default='bfs_greedy')
    parser.add_argument('--droidbot_interval', type=int, default=1)
    parser.add_argument('--droidbot_timeout', type=int, default=1800)
    parser.add_argument('--droidbot_count', type=int, default=600)
    parser.add_argument('--droidbot_output_subdir', type=str, default='droidbot_output')
    parser.add_argument('--droidbot_is_emulator', action='store_true')

    args = parser.parse_args()

    algo = "droidbot"



    apks = scan_file(args.apps)
    result_base_dir = os.path.join("analysis", "droidbot")
    os.makedirs(result_base_dir, exist_ok=True)
    processed_success_path = os.path.join(result_base_dir, "processed_success.txt")
    processed_failed_path = os.path.join(result_base_dir, "processed_failed.txt")
    coverage_path = os.path.join(result_base_dir, "coverage.txt")

    logger.info("🚀 独立 DroidBot 探索脚本启动")
    adb_connect(ADB_DEVICE)

    try:
        for application in apks:
            gc.collect()
            config.thread_life = True
            config.frida_ready = False
            config.frida_last_error = ""
            config.frida_hard_failed = False
            config.frida_last_ok_ts = 0.0
            config.frida_current_package = ""
            config.frida_target_top_seen_ts = 0.0
            config.frida_has_ever_ready = False


            app = None
            network_monitor = None
            coverage_rate = 0.0
            app_success_flag = False
            failure_reason = "Unknown"

            app_name = os.path.basename(os.path.splitext(application)[0])

            raw_activity_info = {}
            appPackage, appActivity, _ = apk_util.parse_pkg(application, raw_activity_info)
            all_activities_list = list(raw_activity_info.keys())

            logger.info("appPackage:" + str(appPackage))
            logger.info("appActivity:" + str(appActivity))

            output_dir = os.path.join("analysis", "droidbot", app_name)
            os.makedirs(output_dir, exist_ok=True)
            lock_file = os.path.join(output_dir, "2nd.lock")

            logger.info(f"🧹 正在为新任务 {app_name} 清理环境...")
            try:
                adb_kill_infra_processes(kill_frida=True, kill_uia=True, kill_atx=True)
                adb_cleanup_uiautomator_residue()
                adb_force_stop(appPackage)
            except Exception as e:
                logger.warning(f"⚠️ DroidBot 模式环境清理失败: {e}")

            if args.stage == 1:
                if os.path.exists(lock_file):
                    os.remove(lock_file)
                adb_pm_clear(appPackage)
                logger.info(f"✨ 阶段 1：准备全新探测 {appPackage}")
            else:
                logger.info(f"🔐 阶段 2：准备带登录态探测 {appPackage}")
                with open(lock_file, 'w') as f:
                    f.write("lock")

            network_monitor = Monitor(appPackage, app_name, ADB_DEVICE, output_base_dir=output_dir, algo=algo)
            network_monitor.start_monitoring(stage=args.stage)

            try:
                app = init_droidbot_frida_context(
                    application=application,
                    appPackage=appPackage,
                    appActivity=appActivity,
                    stage=args.stage,
                    warmup_sec=12
                )

                logger.info(f"🛡️ [Audit] 正在追溯启动阶段 ({app.app_start_time}) 的 API 调用...")

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

            except RuntimeError as e:
                logger.error(f"💥 App {app_name} 初始化失败，跳过。错误: {e}")
                record_status(app_name, "failed", f"InitRuntimeError:{str(e)[:150]}", processed_success_path, processed_failed_path)
                if network_monitor and network_monitor.is_monitoring:
                    network_monitor.stop_monitoring()
                adb_force_stop(appPackage)
                continue

            except Exception as e:
                error_traceback = traceback.format_exc()
                logger.error(f"💥 App {app_name} 初始化失败 (通用异常)")
                logger.error(f"   错误类型: {type(e).__name__}")
                logger.error(f"   错误信息: {e}")
                logger.error(f"   完整堆栈:\n{error_traceback}")
                record_status(app_name, "failed", f"InitException:{type(e).__name__}", processed_success_path,
                              processed_failed_path)
                if network_monitor and network_monitor.is_monitoring:
                    network_monitor.stop_monitoring()
                adb_force_stop(appPackage)
                continue

            try:
                logger.info(f"🤖 开始独立 DroidBot 探索: {app_name}")

                logger.info("🤖 [DroidBot] 不预先拉起 App，交由 DroidBot 自主启动")
                flush_sensitive_apis(app, tag="BEFORE_DROIDBOT", save_dump=True)
                adb_cleanup_uiautomator_residue()

                droidbot_out = run_droidbot_exploration(
                    application=application,
                    appPackage=appPackage,
                    app_name=app_name,
                    output_dir=output_dir,
                    args=args,
                    app=app
                )

                flush_sensitive_apis(app, tag="AFTER_DROIDBOT", save_dump=True)

                coverage_rate, matched, visited = collect_droidbot_coverage(
                    droidbot_out=droidbot_out,
                    all_activities_list=all_activities_list,
                    appPackage=appPackage
                )

                with open(os.path.join(output_dir, "droidbot_visited_activities.txt"), "w", encoding="utf-8") as f:
                    f.write("=== matched activities ===\n")
                    for x in sorted(matched):
                        f.write(x + "\n")
                    f.write("\n=== all visited activities ===\n")
                    for x in sorted(visited):
                        f.write(x + "\n")

                logger.info(
                    f"[droidbot-S{args.stage}] {app_name} | "
                    f"Activity coverage rate: {coverage_rate:.4f} "
                    f"({len(matched)}/{len(all_activities_list) if len(all_activities_list) > 0 else 0})"
                )

                app_success_flag = True


            except FridaMonitorDiedError as e:

                app_success_flag = False

                failure_reason = f"FridaMonitorDied:{str(e)[:200]}"

                logger.error(

                    f"❌ 当前 app 判定失败：Frida 在 DroidBot 运行期间异常/中断。"

                    f"\nReason: {e}\n{traceback.format_exc()}"

                )

            except DroidBotTimeoutError:
                app_success_flag = False
                failure_reason = "DroidBotTimeout"
                logger.error(f"❌ 当前 app 判定失败：DroidBot 超时。\n{traceback.format_exc()}")

            except Exception as e:
                app_success_flag = False
                failure_reason = f"DroidBotError:{type(e).__name__}"
                logger.error(f"❌ DroidBot 探索失败:\n{traceback.format_exc()}")

            finally:
                flush_sensitive_apis(app, tag="FINAL_DROIDBOT_FLUSH", save_dump=True)
                persist_sensitive_api_records(app, app_name, algo="droidbot")

                with open(coverage_path, 'a', encoding='utf-8') as f:
                    f.write(f"App: {app_name} | Algo: droidbot | Stage: {args.stage} | Coverage: {coverage_rate:.4f}\n")

                if app_success_flag:
                    record_status(app_name, "success", success_file=processed_success_path, failed_file=processed_failed_path)
                    try:
                        shutil.move(
                            str(Path(args.apps) / f"{app_name}.apk"),
                            str(Path(args.apps_explored) / f"{app_name}.apk")
                        )
                    except Exception as e:
                        logger.warning(f"APK 移动失败: {e}")
                else:
                    record_status(app_name, "failed", failure_reason, processed_success_path, processed_failed_path)

                config.thread_life = False

                if network_monitor and network_monitor.is_monitoring:
                    network_monitor.stop_monitoring()

                stop_droidbot_frida_context(app)
                adb_force_stop(appPackage)

                logger.info(f"✅ App {app_name} DroidBot 分析完成")

    except Exception:
        logger.error(f"❌ 严重运行异常: {traceback.format_exc()}")
    finally:
        config.thread_life = False
        logger.info("🏁 独立 DroidBot 任务结束，环境已清理。")


if __name__ == '__main__':
    main()