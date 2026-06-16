# RLApplicationEnv.py
import re
import os
import numpy as np
import time
import json
from multiprocessing import Process, Queue
import random
from xml.etree import ElementTree as ET
from utils.widget_util import parse_widgets, is_input_like_item
from utils.screen_util import get_screen
from entity_dao.widget import Widget
from entity_dao.GUI import GUI
import torch
from models.autoencoder import ScreenLayout
import imgsim
from sentence_transformers import SentenceTransformer
from models.widget_embed import WidgetEmbed
from models.autoencoder import LayoutAutoEncoder
from monitoring import papi_monitor
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed  # ✅ 新增
import queue  # ✅ 新增
from utils.adbHelper import checkPackageInstall, dump_layout, get_current_activity, screencap
from utils.monitoring_utils import install_app_and_install_frida, install_frida
import config
from loguru import logger
from utils.widget_util import generate_udid_str
import uuid
from datetime import datetime
from utils.img_sim_hash import img_hash_distance
import traceback
from utils.adbHelper import start_activity
from utils.screen_util import image_match, get_class_list
import Levenshtein
from utils.screen_util import save_gui_image, save_json_file, save_xml_file
import subprocess
from utils.driver_manager import driver_manager
import hashlib
from collections import defaultdict


class RLApplicationEnv():
    # ✅ 类级别常量
    INPUT_KEYWORDS = {
        "用户名": "testuser123", "账号": "testuser123",
        "密码": "Test123456", "口令": "Test123456",
        "登录密码": "Test123456", "确认密码": "Test123456",
        "重复密码": "Test123456", "新密码": "Test123456", "旧密码": "Test123456",
        "邮箱": "yanjunbi19@example.com",
        "手机号": "13664848947", "手机号码": "13664848947",
        "电话": "13664848947", "电话号码": "13664848947",
        "验证码": "123456",
        "姓名": "TestUser", "年龄": "25",
        "生日": "1998-01-01", "出生日期": "1998-01-01",
        "性别": "男",
        "地址": "Beijing", "详细地址": "Beijing",
        "城市": "Beijing", "省份": "Beijing", "国家": "China",
        "邮编": "100000", "邮政编码": "100000",
        "搜索": "test", "关键词": "test", "查询": "test",
        "输入关键字": "test", "请输入": "test",
        "评论": "test comment",
    }

    # ✅ 预编译正则表达式（提升性能）
    _STRUCTURE_PATTERN = re.compile(r'class="([^"]*)"|resource-id="([^"]*)"')

    def __init__(self, params, appPackage, appActivity, application, bert, layout_autoencoder, vtr,
                 allActivities, device_address):
        self.num_actions = params.num_actions
        self.dm = driver_manager
        self.appPackage = appPackage
        self.appActivity = appActivity
        self.allActivities = allActivities
        self.stage = params.stage
        self.timesteps = 0
        self.algo = params.algo

        self.visited_states = set()
        self.current_state_id = None
        self.executed_widget = None
        self.all_sensitive_api_list = []
        self.GUI_dict = set()
        self.all_widget_dict = {}
        self.visited_api_state_pairs = set()
        self.last_manual_time = 0
        self.current_manual_dir = None
        self.api_pair_counts = defaultdict(int)  # (state_id, api_sig) -> times
        self.state_api_hits = defaultdict(int)  # state_id -> total api hits (not unique)
        self.last_structure_signature = None

        self.seen_state_api_pairs = set()  # (state_id, api_sig) seen in current episode

        # ✅ 缓存设备类型，避免重复判断
        self._device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self._screen_area = config.Device_resolution_x * config.Device_resolution_y

        # ✅ 创建线程池（用于并行 UI 获取）
        self._ui_executor = ThreadPoolExecutor(max_workers=3)

        # ✅ 异步保存队列和线程
        self._save_queue = queue.Queue()
        self._save_thread = Thread(target=self._async_save_worker, daemon=True)
        self._save_thread.start()
        if self.algo == 'random':
            self.layout_autoencoder = None
            self.vtr = None
            self.bert = None
            logger.info("🚀 Random 策略：跳过所有模型加载")
        # --- 1. 模型加载 ---
        else:
            self.layout_autoencoder = layout_autoencoder
        if self.layout_autoencoder is not None:
            self.layout_autoencoder.to(self._device).eval()
        else:
            logger.info("算法为 Random，跳过 layout_autoencoder 加载")

        self.vtr = vtr if vtr is not None else None
        self.bert = bert if bert is not None else None
        self._last_action_sig = None
        self._repeat_count = 0

        # --- 2. 阶段性安装逻辑 ---
        if self.stage == 1:
            logger.info("🛠️ 阶段 1：全新安装 App 并推送 Frida")
            # install_app_and_install_frida(application, appPackage, appActivity)
            install_frida(application, appPackage, appActivity)
        else:
            logger.info("⏩ 阶段 2：跳过安装，直接检查 App 存在性")
            install_frida(application, appPackage, appActivity)
            if not checkPackageInstall(appPackage):
                raise Exception(f"❌ 阶段 2 失败：应用 {appPackage} 未安装")
        # --- 3. 启动 Frida 监控线程 ---
        self.monitoring_thread = Thread(
            target=papi_monitor.start_monitoring,
            args=(self.appPackage, self.stage, self.algo),
            daemon=True
        )
        self.monitoring_thread.start()
        logger.info("⏳ 等待 Frida Hooks 注入...")
        if not self.monitoring_thread.is_alive():
            logger.error("❌ Frida 监控线程在 Hook 完成前或启动过程中死亡。强制终止该 App。")
            raise RuntimeError("Frida Monitoring Thread died.")
        # ✅ 智能等待 App 启动
        self._wait_for_app_ready(max_wait=10)

        # 检查线程健康
        is_ok = False
        for _ in range(5):
            if self.monitoring_thread.is_alive():
                is_ok = True
                break
            logger.warning("Frida 线程已死亡，App 可能启动失败。")
            time.sleep(2)

        if not is_ok:
            raise RuntimeError("Frida 监控线程未能成功启动 App 进程。")
        self.api_trigger_counts = defaultdict(int)
        self.decay_rate = 0.5  # 可通过 params 传入
        logger.info('✅ RL环境已就绪，准备开始探索。')
        self.refreshNewObservation()
        self.un_variable_num = 0
        # 1. API 奖励配置
        self.api_reward_mode = getattr(params, 'api_reward_mode', 2)
        self.W_api = getattr(params, 'W_api', 10.0)

        # 2. 控件探索奖励配置 (Widget)
        self.widget_reward_mode = getattr(params, 'widget_reward_mode', 1)
        self.W_wid = getattr(params, 'W_wid', 0.5)
        # 3. 状态/Activity 探索奖励配置 (Exploration)
        self.state_reward_mode = getattr(params, 'state_reward_mode', 1)
        self.R_new = getattr(params, 'R_new', 10.0)
        self.R_escape = getattr(params, 'R_escape', 12.0)
        self.R_old = getattr(params, 'R_old', -2.0)

        # 4. 困境惩罚配置 (Penalty)
        self.stuck_penalty_mode = getattr(params, 'stuck_penalty_mode', 1)
        self.P_red = getattr(params, 'P_red', -15.0)
        logger.info(
            f"💡 Reward Ablation Modes: API={self.api_reward_mode}, State={self.state_reward_mode}, Widget={self.widget_reward_mode}")

    def _wait_for_app_ready(self, max_wait=10):
        """智能等待 App 启动完成，而非固定等待"""
        start_time = time.time()
        while time.time() - start_time < max_wait:
            try:
                info = self.dm.app_current()
                if info and info.get('package') == self.appPackage:
                    elapsed = time.time() - start_time
                    logger.info(f"✅ App 已启动 (耗时 {elapsed:.1f}s)")
                    time.sleep(1)  # 额外等待 UI 稳定
                    return True
            except:
                pass
            time.sleep(0.5)

        logger.warning(f"⚠️ App 启动等待超时 ({max_wait}s)")
        return False

    # =========================================================================
    # ✅ 核心优化：并行获取 UI 数据的函数
    # =========================================================================
    # def _fetch_ui_data_serial(self, timeout=10):
    #     """
    #     改为串行获取 UI 数据，解决并行导致的 UIAutomator2 不稳定和 NullPointerException 问题。
    #     """
    #     results = {
    #         'page_source': None,
    #         'screenshot': None,
    #         'app_info': {}
    #     }
    #
    #     # 1. 获取当前 App 信息 (最轻量，优先执行)
    #     try:
    #         results['app_info'] = self.dm.app_current()
    #     except Exception as e:
    #         logger.debug(f"app_current 失败: {e}")
    #         results['app_info'] = {}
    #     # 在两个重型操作之间稍微留一点点喘息时间（可选，增加稳定性）
    #     time.sleep(0.1)
    #     # 2. 获取 UI 层次结构 (最容易崩溃的操作)
    #     try:
    #         # 使用你包装好的 safe_dump_hierarchy
    #         results['page_source'] = self.dm.safe_dump_hierarchy(compressed=True)
    #     except Exception as e:
    #         logger.warning(f"dump_hierarchy 串行获取失败: {e}")
    #         results['page_source'] = None
    #     time.sleep(0.1)
    #     # 3. 获取截图
    #     # try:
    #     #     # 注意：如果 dm.screenshot() 没响应，确保它内部有超时机制
    #     #     results['screenshot'] = self.dm.screenshot()
    #     # except Exception as e:
    #     #     logger.warning(f"screenshot 串行获取失败: {e}")
    #     #     results['screenshot'] = None
    #     results['screenshot'] = None
    #     return results
    def _fetch_ui_data_serial(self, timeout=10):
        """串行获取 UI 数据，增加错误恢复"""
        results = {
            'page_source': None,
            'screenshot': None,
            'app_info': {}
        }

        # 1. 获取 App 信息
        try:
            results['app_info'] = self.dm.app_current()
        except Exception as e:
            logger.debug(f"app_current 失败: {e}")
            results['app_info'] = {}

        time.sleep(0.2)  # ✅ 增加间隔，避免并发冲突

        # 2. 获取 UI 层次结构（最容易出错的操作）
        for retry in range(3):  # ✅ 增加内部重试
            try:
                results['page_source'] = self.dm.safe_dump_hierarchy(compressed=True)
                if results['page_source']:
                    break
                logger.warning(f"dump_hierarchy 返回空，重试 {retry + 1}/3")
                time.sleep(1)
            except Exception as e:
                logger.warning(f"dump_hierarchy 异常 ({retry + 1}/3): {str(e)[:80]}")
                if "NullPointerException" in str(e):
                    # ✅ 如果是 AccessibilityService 问题，等待更久
                    time.sleep(3)
                else:
                    time.sleep(1)

        time.sleep(0.2)

        # 3. 获取截图
        try:
            results['screenshot'] = self.dm.screenshot()
        except Exception as e:
            logger.warning(f"screenshot 失败: {e}")
            results['screenshot'] = None

        return results

    # =========================================================================
    # ✅ 异步保存数据
    # =========================================================================

    def _async_save_worker(self):
        """异步保存工作线程"""
        while True:
            try:
                task = self._save_queue.get(timeout=1)
                if task is None:  # 退出信号
                    break
                self._do_save_dumps(*task)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"异步保存失败: {e}")

    def _queue_save_dumps(self, sens_api_list, widget, screenshot, layout):
        """将保存任务加入队列（非阻塞）"""
        self._save_queue.put((sens_api_list, widget, screenshot, layout))

    def _do_save_dumps(self, sens_api_list, widget, screenshot, layout):
        """实际执行保存操作"""
        try:
            os.makedirs('dumps/' + self.appPackage, exist_ok=True)
            dir_time = datetime.now().strftime("%Y%m%d%H%M%S")
            dir_time_path = os.path.join('dumps', self.appPackage, dir_time)
            os.makedirs(dir_time_path, exist_ok=True)

            save_gui_image(
                path=dir_time_path,
                img_dict={'ui_at_trigger': screenshot},
                quality=10,
                scale=0.3
            )
            save_xml_file(path=dir_time_path, xml_dict={'xml_at_trigger': layout})
            save_json_file(path=dir_time_path, json_dict={
                'api_name_list': sens_api_list,
                'op_widget_text': widget.text,
                'op_widget_bounds': widget.bounds,
                'timestamp': dir_time
            })

        except Exception as e:
            logger.error(f"保存 dumps 失败: {e}")

    # =========================================================================
    # 其他方法
    # =========================================================================

    def grant_permissions(self):
        permissions = ['android.permission.ACCESS_WIFI_STATE']
        for permission in permissions:
            try:
                self.dm.shell(f'pm grant {self.appPackage} {permission}')
            except Exception as e:
                logger.warning(f"Failed to grant permission {permission}: {e}")

    def get_state_id(self, xml_str):
        activity_name = getattr(self, "current_activity", "unknown_activity")
        return self._make_state_id(xml_str, activity_name)

    def _find_escape_widget_ids(self):
        candidates = []
        for widget_id in self.usable_widgets:
            widget = self.all_widget_dict.get(widget_id)
            if not widget:
                continue
            text = str(widget.text).lower()
            res_id = str(widget.resource_id).lower()
            blob = text + " " + res_id
            if any(k in blob for k in [
                "close", "dismiss", "cancel", "done", "back", "return",
                "关闭", "取消", "返回", "退出", "我知道了", "跳过"
            ]):
                candidates.append(widget_id)
        return candidates

    def _recover_from_stuck(self, prev_state_id):
        recovered = False
        # 1) 优先点击关闭/返回控件
        for widget_id in self._find_escape_widget_ids():
            widget = self.all_widget_dict.get(widget_id)
            if not widget:
                continue
            try:
                self.perform_touch_action(widget)
                time.sleep(0.8)
                self.refreshNewObservation()
                if self.current_state_id != prev_state_id:
                    recovered = True
                    break
            except Exception:
                pass
        # 2) 系统 back
        if not recovered:
            try:
                self.dm.press("back")
                time.sleep(0.8)
                self.refreshNewObservation()
                if self.current_state_id != prev_state_id:
                    recovered = True
            except Exception:
                pass
        # 3) 点击顶部安全区
        if not recovered:
            try:
                self.dm.click(config.Device_resolution_x / 2, 120)
                time.sleep(0.8)
                self.refreshNewObservation()
                if self.current_state_id != prev_state_id:
                    recovered = True
            except Exception:
                pass
        return recovered

    def _build_structure_signature(self, xml_str):
        if not xml_str:
            return "empty"
        matches = self._STRUCTURE_PATTERN.findall(xml_str)
        if not matches:
            return "empty"
        # 统计 token，避免顺序抖动导致签名抖动
        counts = defaultdict(int)

        def _norm_res_id(res_id: str) -> str:
            # 保守归一化：去掉数字段，降低动态 suffix 的影响
            # 例：com.xx:id/item_12 -> com.xx:id/item_
            res_id = res_id.strip()
            res_id = re.sub(r"\d+", "", res_id)
            res_id = re.sub(r"_+", "_", res_id)
            return res_id

        for cls_name, res_id in matches:
            if cls_name:
                counts["c:" + cls_name] += 1
            if res_id:
                counts["r:" + _norm_res_id(res_id)] += 1
        # 只取 TopK，避免签名过长（K 可调，先 120）
        items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:120]
        return "|".join([f"{k}#{v}" for k, v in items])

    # 2) refreshNewObservation：修 activity 同步 + app_info 取值
    def refreshNewObservation(self, prefetched_xml=None):
        retry_limit = 5
        page_source = ""
        current_screen = None
        labeled_text = []
        current_activity = ""
        use_prefetched = prefetched_xml is not None
        for i in range(retry_limit):
            try:
                # 先检查 app 在前台
                app_info = self.dm.app_current() or {}
                current_package = app_info.get('package', '')
                if current_package != self.appPackage:
                    logger.warning(f"⚠️ App 不在前台 ({current_package})，尝试切回...")
                    self.dm.app_start(self.appPackage)
                    time.sleep(3)
                    continue
                if use_prefetched:
                    page_source = prefetched_xml
                    current_screen = self.dm.screenshot()
                    # 关键：prefetch 场景也重新取一次 activity，保证和 page_source 同步
                    app_info = self.dm.app_current() or {}
                    use_prefetched = False
                else:
                    ui_data = self._fetch_ui_data_serial()
                    page_source = ui_data['page_source']
                    current_screen = ui_data['screenshot']
                    # 关键：用与 dump 同批次的 app_info
                    app_info = ui_data.get('app_info') or app_info
                current_activity = app_info.get('activity', '')
                if not page_source or current_screen is None:
                    logger.warning(f"⏳ UI 数据无效，重试 ({i + 1}/{retry_limit})")
                    time.sleep(1)
                    continue
                xmlRoot = ET.fromstring(page_source)
                labeled_text = parse_widgets(xmlRoot, False, False, testing=False)
                if len(labeled_text) >= 3:
                    break
                logger.warning(f"⏳ 控件过少 ({len(labeled_text)})，等待... ({i + 1}/{retry_limit})")
                time.sleep(0.5)
            except Exception as e:
                logger.warning(f"⚠️ UI 获取异常 ({i + 1}/{retry_limit}): {str(e)[:100]}")
                if "NullPointerException" in str(e):
                    logger.error("检测到 AccessibilityService 崩溃，等待恢复...")
                    time.sleep(5)
                else:
                    time.sleep(2)
        if not page_source or current_screen is None:
            raise RuntimeError(f"无法从 {self.appPackage} 获取有效的 UI 数据")
        self.last_page_source = page_source
        self.last_screenshot = current_screen
        self.current_activity = current_activity
        self.last_structure_signature = self._build_structure_signature(page_source)
        self.current_state_id = self.get_state_id(page_source)
        self.GUI_dict.add(self.current_activity)
        # 特征提取等后续逻辑保持不变...
        self.layout_feature = self.get_layout_feature(page_source) if self.layout_autoencoder else torch.zeros(1, 64,
                                                                                                               device=self._device)
        self.visual_feature = self.get_visual_feature(current_screen) if self.vtr else torch.zeros(1, 768,
                                                                                                   device=self._device)

        # --- 阶段 3: 控件过滤与排序 ---
        def _widget_text_blob(item):
            text = str(item[0]).lower() if len(item) > 0 else ""
            res_id = str(item[4]).lower() if len(item) > 4 else ""
            content_desc = str(item[7]).lower() if len(item) > 7 else ""
            class_string = str(item[5]).lower() if len(item) > 5 else ""
            return " ".join([text, res_id, content_desc, class_string])

        def _is_close_or_back_candidate(item):
            blob = _widget_text_blob(item)
            close_keywords = [
                '×', 'close', 'dismiss', 'cancel', 'done', 'back', 'return', 'up',
                '关闭', '取消', '返回', '退出', '上一步', 'nav', 'navigate', "跳过"
            ]
            if any(k in blob for k in close_keywords):
                return True
            # 位置启发：右上角/左上角的小按钮
            if len(item) > 2 and item[2]:
                left, top, right, bottom = item[2]
                screen_w = config.Device_resolution_x
                screen_h = config.Device_resolution_y
                if screen_w and screen_h:
                    in_top = top < 0.18 * screen_h
                    in_left = left < 0.18 * screen_w
                    in_right = right > 0.82 * screen_w
                    if in_top and (in_left or in_right):
                        class_string = str(item[5]).lower() if len(item) > 5 else ""
                        if 'imagebutton' in class_string or 'button' in class_string:
                            return True
            return False

        def _action_sig_for_item(item):
            # Stable signature: prefer resource-id, else bounds+class+desc
            rid = str(item[4] or "").strip() if len(item) > 4 else ""
            b = item[2] if len(item) > 2 else None
            cls = str(item[5] or "").strip() if len(item) > 5 else ""
            desc = str(item[7] or "").strip() if len(item) > 7 else ""
            if rid:
                return ("tap", "rid", rid)
            if b:
                return ("tap", "b", tuple(b), "c", cls, "d", desc)
            return ("tap", "c", cls, "d", desc)

        def get_widget_priority(item):
            score = 0
            text = str(item[0] or "").lower()
            res_id = str(item[4] or "").lower() if len(item) > 4 else ""
            content_desc = str(item[7] or "").lower() if len(item) > 7 else ""
            class_string = str(item[5] or "").lower() if len(item) > 5 else ""
            blob = " ".join([text, res_id, content_desc, class_string])
            # Base: interactive > labels
            oper = int(item[3]) if len(item) > 3 else 0
            if oper == 2:
                score += 90
            elif oper == 1:
                score += 160
            else:
                score += 5
            # Input/search boost (generic)
            if is_input_like_item(item):
                score += 260
            # text presence a bit helpful
            if text or content_desc:
                score += 40
            # keep your existing heuristics
            if any(k in blob for k in ['tab', 'btn', 'button', 'menu', 'item', 'entry']):
                score += 25
            if _is_close_or_back_candidate(item):
                score += 120  # still prefer escape sometimes, but less dominating
            # Strong repeated-click penalty
            sig = _action_sig_for_item(item)
            if self._last_action_sig is not None and sig == self._last_action_sig:
                score -= 180 * max(1, self._repeat_count)
            return score

        operatable_list = []
        for item in labeled_text:
            if item[3] in [1, 2]:
                b = item[2]
                area = (b[2] - b[0]) * (b[3] - b[1])
                is_close_or_back = _is_close_or_back_candidate(item)
                is_input_like = is_input_like_item(item)
                # Filter only obvious junk:
                # - huge background containers with no text/desc/res-id and not input-like
                if (area > 0.55 * self._screen_area
                        and not item[0]
                        and not str(item[4] or "").strip()
                        and not str(item[7] or "").strip()
                        and not is_input_like):
                    continue
                # - tiny noise (but keep if close/back or input-like)
                if area < 24 and (not is_close_or_back) and (not is_input_like):
                    continue
                operatable_list.append(item)
        operatable_list.sort(key=get_widget_priority, reverse=True)
        # --- 阶段 4: 构建可用动作空间 ---
        self.usable_widgets = []
        widget_texts = []
        widget_visit_counts = []
        widget_shallow_visit_counts = []
        for item in operatable_list:
            if len(self.usable_widgets) >= self.num_actions:
                break
            udid_str = generate_udid_str(self.current_activity, item)
            widget_udid = str(uuid.uuid3(uuid.NAMESPACE_DNS, udid_str))
            if widget_udid not in self.all_widget_dict:
                raw_class = str(item[5]) if len(item) > 5 else ""
                is_input = ("EditText" in raw_class or "Search" in raw_class)
                new_widget = Widget(
                    item[0],
                    item[1],
                    item[2],
                    item[3],
                    widget_udid,
                    current_screen,
                    resource_id=item[4],
                    class_string=item[5],
                    scrollable=item[6],
                    content_desc=item[7],
                    index=item[8]
                )
                new_widget.is_input_field = is_input
                self.all_widget_dict[widget_udid] = new_widget
            poten_widget = self.all_widget_dict[widget_udid]
            self.usable_widgets.append(widget_udid)
            widget_visit_counts.append(poten_widget.visitCount)
            widget_shallow_visit_counts.append(poten_widget.shallow_visitCount)
            temp_item = list(item)
            temp_item[2] = [
                item[2][0] / config.Device_resolution_x, item[2][1] / config.Device_resolution_y,
                item[2][2] / config.Device_resolution_x, item[2][3] / config.Device_resolution_y
            ]
            widget_texts.append(temp_item)
        # --- 阶段 5: 状态转移与动作掩码 ---
        if self.executed_widget is not None:
            self.executed_widget.nextGUIWidgetSet.update(self.usable_widgets)
            self.executed_widget.maxVisitCount = len(self.executed_widget.nextGUIWidgetSet)
        self.current_mask = [0] * self.num_actions
        for i in range(len(self.usable_widgets)):
            self.current_mask[i] = 1
        # --- 阶段 6: 构建最终 Observation ---
        self.observation = [
            self.visual_feature.to(self._device),  # (1,768)
            self.layout_feature.to(self._device),  # (1,64)
            [widget_texts],
            [widget_visit_counts],
            [widget_shallow_visit_counts],
            self.current_mask
        ]
        return True

    def get_visual_feature(self, screen_shot):
        """获取视觉特征 (imgsim 0.1.1 Vectorizer) -> torch tensor (1, 768)"""
        if self.vtr is None or screen_shot is None:
            return torch.zeros(1, 768, device=self._device)

        try:
            # uiautomator2 screenshot 常见是 PIL.Image；这里统一转成 np.uint8 (H,W,3)
            if isinstance(screen_shot, np.ndarray):
                img = screen_shot
            else:
                img = np.array(screen_shot)

            if img is None:
                return torch.zeros(1, 768, device=self._device)

            # 去掉 alpha 通道
            if img.ndim == 3 and img.shape[2] == 4:
                img = img[:, :, :3]
            # 灰度图转 3 通道
            if img.ndim == 2:
                img = np.stack([img, img, img], axis=-1)

            img = img.astype(np.uint8, copy=False)

            # imgsim.Vectorizer.vectorize 期望输入: uint8 (H,W,3)
            vec = self.vtr.vectorize(img)  # np.ndarray shape (768,)

            return torch.from_numpy(vec).float().unsqueeze(0).to(self._device).detach()

        except Exception as e:
            logger.warning(f"视觉特征提取异常: {e}")
            return torch.zeros(1, 768, device=self._device)

    def get_layout_feature(self, page_source):
        """获取布局特征"""
        if self.layout_autoencoder is None:
            return torch.zeros(1, 64, device=self._device)

        try:
            layout_embedder = self.layout_autoencoder.enc
            screen_to_add = ScreenLayout(page_source)
            screen_pixels = screen_to_add.pixels.flatten()

            with torch.no_grad():
                encoded_layout = layout_embedder(
                    torch.as_tensor(screen_pixels, dtype=torch.float).unsqueeze(0).to(self._device)
                )
            return encoded_layout.detach()
        except Exception as e:
            logger.warning(f"布局特征提取异常: {e}")
            return torch.zeros(1, 64, device=self._device)

    def checkSensitiveAPIs(self):
        sense_api_trigged_list = list(config.api_trigged_list)
        if len(sense_api_trigged_list) > 0:
            config.api_trigged_list.clear()
        return sense_api_trigged_list

    def checkAppStatus(self):
        try:
            current_info = self.dm.app_current()
            if current_info and current_info.get('package') == self.appPackage:
                return 1
            return -1
        except:
            return -1

    def step(self, operatable_widget):
        self.timesteps += 1
        if not hasattr(self, "_filled_input_signatures"):
            self._filled_input_signatures = set()
        pre_action_state_id = self.current_state_id
        layout_before_op = self.last_page_source
        old_gui = self.last_screenshot
        current_activity = (self.dm.app_current() or {}).get('activity', 'unknown')

        input_performed = False
        action_widget_for_repeat = operatable_widget

        is_edit_text = getattr(operatable_widget, "is_input_field", False)
        if is_edit_text:
            w = operatable_widget
            logger.info(f"Batch input triggered for widget: {getattr(w, 'text', '')}")

            blob = " ".join([
                str(getattr(w, "text", "") or ""),
                str(getattr(w, "resource_id", "") or ""),
                str(getattr(w, "content_desc", "") or ""),
                str(getattr(w, "class_string", "") or ""),
            ]).lower()

            target_text = "test"
            for kw, val in self.INPUT_KEYWORDS.items():
                if (kw or "").lower() in blob:
                    target_text = val
                    break

            # 关键：signature 不能包含 text（text 会变，导致永远当成“新输入框”）
            rid = str(getattr(w, "resource_id", "") or "").strip()
            bounds = getattr(w, "bounds", None)
            bounds = str(bounds).strip() if bounds is not None else ""
            cls = str(getattr(w, "class_string", "") or "").strip()
            desc = str(getattr(w, "content_desc", "") or "").strip()

            if rid:
                sig = f"rid:{rid}"
            elif bounds:
                sig = f"b:{bounds}|c:{cls}"
            else:
                sig = f"d:{desc}|c:{cls}"

            if sig not in self._filled_input_signatures:
                self.perform_adb_input(w, "batch", target_text)
                self._filled_input_signatures.add(sig)

                # 输入完尽量让页面发生变化：回车 + 收键盘
                try:
                    self.dm.shell("input keyevent 66")  # Enter
                    self.dm.shell("input keyevent 4")  # Back (hide keyboard)
                except Exception:
                    pass

                input_performed = True

            else:
                # 已经填过的输入框不要再输入（否则会出现 testtesttest 循环）
                self.perform_touch_action(w)

            action_widget_for_repeat = w

        else:
            self.perform_touch_action(operatable_widget)

            # Post-click input attempt: many apps use a clickable container to open an EditText.
            try:
                blob = " ".join([
                    str(getattr(operatable_widget, "text", "") or ""),
                    str(getattr(operatable_widget, "resource_id", "") or ""),
                    str(getattr(operatable_widget, "content_desc", "") or ""),
                    str(getattr(operatable_widget, "class_string", "") or ""),
                ]).lower()
                input_keys = ("search", "query", "keyword", "filter", "input", "请输入", "搜索", "查询", "关键字",
                              "筛选")
                maybe_input_entry = any(k in blob for k in input_keys)
            except Exception:
                maybe_input_entry = False
            if maybe_input_entry:
                # 不提前 refresh；只预取点击后的 xml，用它来解析输入框
                old_sig2 = self.last_structure_signature or self._build_structure_signature(layout_before_op)
                clicked_xml = self._wait_for_ui_change(old_sig2, max_wait=1.2)

                if clicked_xml:
                    try:
                        xmlRoot2 = ET.fromstring(clicked_xml)
                        labeled_text2 = parse_widgets(xmlRoot2, False, False, testing=False)

                        # 从 labeled_text2 里找最可能的输入框（EditText/Search）
                        best_item = None
                        best_score = -10 ** 9

                        for item in labeled_text2:
                            # item: [text, xpath, bounds, operatable, resource-id, class, scrollable, content-desc, index]
                            cls2 = str(item[5] or "").lower() if len(item) > 5 else ""
                            rid2 = str(item[4] or "").lower() if len(item) > 4 else ""
                            txt2 = str(item[0] or "").lower() if len(item) > 0 else ""
                            desc2 = str(item[7] or "").lower() if len(item) > 7 else ""
                            blob2 = " ".join([txt2, rid2, desc2, cls2])

                            score = 0
                            is_input = ("edittext" in cls2) or ("search" in cls2) or ("input" in cls2)
                            if is_input:
                                score += 1000
                            if any(k in blob2 for k in ("search", "query", "input", "请输入", "搜索", "查询")):
                                score += 200

                            oper = int(item[3]) if len(item) > 3 else 0
                            if oper == 1:
                                score += 50

                            if score > best_score:
                                best_score = score
                                best_item = item

                        if best_item is not None and best_score >= 200:
                            # 用 best_item 构造一个临时 Widget，用于 adb input（不依赖 refresh 后的 all_widget_dict）
                            raw_class = str(best_item[5]) if len(best_item) > 5 else ""
                            tmp_widget = Widget(
                                best_item[0],
                                best_item[1],
                                best_item[2],
                                best_item[3],
                                "tmp_input_widget",
                                None,
                                resource_id=best_item[4],
                                class_string=best_item[5],
                                scrollable=best_item[6],
                                content_desc=best_item[7],
                                index=best_item[8]
                            )
                            tmp_widget.is_input_field = ("EditText" in raw_class or "Search" in raw_class)

                            tmp_blob = " ".join([
                                str(getattr(tmp_widget, "text", "") or ""),
                                str(getattr(tmp_widget, "resource_id", "") or ""),
                                str(getattr(tmp_widget, "content_desc", "") or ""),
                                str(getattr(tmp_widget, "class_string", "") or ""),
                            ]).lower()

                            target_text = "test"
                            for kw, val in self.INPUT_KEYWORDS.items():
                                if (kw or "").lower() in tmp_blob:
                                    target_text = val
                                    break

                            rid = str(getattr(tmp_widget, "resource_id", "") or "").strip()
                            bounds = str(getattr(tmp_widget, "bounds", "") or "").strip()
                            cls = str(getattr(tmp_widget, "class_string", "") or "").strip()
                            desc = str(getattr(tmp_widget, "content_desc", "") or "").strip()

                            if rid:
                                sig = f"rid:{rid}"
                            elif bounds:
                                sig = f"b:{bounds}|c:{cls}"
                            else:
                                sig = f"d:{desc}|c:{cls}"

                            if sig not in self._filled_input_signatures:
                                self.perform_adb_input(tmp_widget, "post_click", target_text)
                                self._filled_input_signatures.add(sig)
                                try:
                                    self.dm.shell("input keyevent 66")
                                    self.dm.shell("input keyevent 4")
                                except Exception:
                                    pass
                                input_performed = True
                                action_widget_for_repeat = tmp_widget

                    except Exception:
                        pass

        old_sig = self.last_structure_signature or self._build_structure_signature(layout_before_op)
        try:
            rid = str(getattr(action_widget_for_repeat, "resource_id", "") or "").strip()
            b = getattr(action_widget_for_repeat, "bounds", None)
            cls = str(getattr(action_widget_for_repeat, "class_string", "") or "").strip()
            desc = str(getattr(action_widget_for_repeat, "content_desc", "") or "").strip()
            if rid:
                sig = ("tap", "rid", rid)
            elif b:
                sig = ("tap", "b", tuple(b), "c", cls, "d", desc)
            else:
                sig = ("tap", "c", cls, "d", desc)
            if self._last_action_sig is not None and sig == self._last_action_sig:
                self._repeat_count += 1
            else:
                self._repeat_count = 0
            self._last_action_sig = sig
        except Exception:
            pass
        prefetched_xml = self._wait_for_ui_change(old_sig, max_wait=2.0)
        self.refreshNewObservation(prefetched_xml=prefetched_xml)

        layout_after_op = self.last_page_source
        new_gui = self.last_screenshot

        xml_score = Levenshtein.seqratio(
            get_class_list(layout_before_op),
            get_class_list(layout_after_op)
        )

        img_same = False
        try:
            if old_gui is not None and new_gui is not None:
                img_same = img_hash_distance(old_gui, new_gui) <= 6
        except Exception as e:
            logger.debug(f"img_hash_distance failed: {e}")
            img_same = False

        same_state = (self.current_state_id == pre_action_state_id)
        high_xml = (xml_score > 0.97)
        votes = int(same_state) + int(high_xml)
        if old_gui is not None and new_gui is not None:
            votes += int(img_same)
        is_stuck = votes >= 2

        was_stuck = (self.un_variable_num > 0)
        recovered = False
        if is_stuck:
            recovered = self._recover_from_stuck(pre_action_state_id)
            if recovered:
                is_stuck = False
                self.un_variable_num = 0

        sens_api_name_list = self.checkSensitiveAPIs()
        if len(sens_api_name_list) > 0:
            self.state_api_hits[pre_action_state_id] += 1
            self._queue_save_dumps(sens_api_name_list, operatable_widget, old_gui, layout_before_op)
        # =======================================================
        # 1. API 奖励计算 (r_api)
        # =======================================================
        if self.algo == 'random':
            # 随机策略：不计算奖励，直接返回
            reward = np.float32(0.0)

            # 但仍需更新卡顿计数器（用于脱困逻辑）
            if is_stuck:
                self.un_variable_num += 1
            else:
                self.un_variable_num = 0

            # 更新控件访问计数（用于统计）
            operatable_widget.add_visit_count()

            info = {
                'activity': current_activity,
                'api_list': sens_api_name_list,
                'is_stuck': is_stuck,
                'recovered': recovered,
                'xml_score': float(xml_score),
                'img_same': bool(img_same),
                'reward_debug': "random_skip",
                'input_performed': bool(input_performed),
            }

            logger.info(
                f"Step {self.timesteps} | [Random] No Reward | "
                f"APIs: {len(sens_api_name_list)} | Stuck: {is_stuck} | "
                f"xml:{xml_score:.3f} | img_same:{img_same}"
            )

            return self.observation, reward, self._termination(), info

        r_api = 0.0
        r_exp = 0.0
        r_wid = 0.0
        r_pen = 0.0
        # =======================================================
        # 1. API 奖励计算 (r_api)
        # =======================================================
        new_pairs = 0
        decay_reward_sum = 0.0  # ✅ 改名，表示累加
        if sens_api_name_list:
            for api_sig in sens_api_name_list:
                # 检查是否是新的 (state, api) 组合
                key_pair = (pre_action_state_id, api_sig)
                if key_pair not in self.seen_state_api_pairs:
                    self.seen_state_api_pairs.add(key_pair)
                    new_pairs += 1

                # 计算指数衰减奖励
                count = self.api_trigger_counts[api_sig]
                decay_reward_sum += self.W_api * (self.decay_rate ** count)  # ✅ 累加

                # ✅ 更新计数
                self.api_trigger_counts[api_sig] += 1
        if self.api_reward_mode == 1:
            # 模式 1: 二进制唯一 API 奖励（只看是否有新pair）
            r_api = self.W_api if new_pairs > 0 else 0.0
        elif self.api_reward_mode == 2:
            # 模式 2: 只有新pair才奖励，但奖励按全局次数衰减
            if new_pairs > 0:
                r_api = decay_reward_sum
            else:
                r_api = 0.0
        elif self.api_reward_mode == 3:
            # 模式 3: 简单命中奖励（不考虑唯一性）
            r_api = self.W_api if len(sens_api_name_list) > 0 else 0.0
        # 模式 0 (关闭) 保持 r_api = 0.0
        # =======================================================
        # 2. 状态探索奖励计算 (r_exp)
        # =======================================================
        if self.state_reward_mode == 1:
            is_new_state = (not is_stuck) and (self.current_state_id not in self.visited_states)
            if is_new_state:
                self.visited_states.add(self.current_state_id)
                r_exp = self.R_new
            elif is_stuck:
                r_exp = 0  # 困境时探索奖励为0
            elif was_stuck or recovered:
                r_exp = self.R_escape
            else:
                r_exp = self.R_old

        # =======================================================
        # 3. 控件探索奖励计算 (r_wid)
        # =======================================================
        if self.widget_reward_mode == 1:
            r_wid = 0 if is_stuck else self.W_wid
        operatable_widget.add_visit_count()
        # =======================================================
        # 4. 困境惩罚计算 (r_pen)
        # =======================================================
        if is_stuck:
            self.un_variable_num += 1
            if self.stuck_penalty_mode == 1:
                # 累积惩罚，防止卡死
                r_pen = self.P_red * 2 if self.un_variable_num > 5 else self.P_red
        else:
            self.un_variable_num = 0
            r_pen = 0.0

        reward = np.float32(r_api + r_exp + r_wid + r_pen)

        info = {
            'activity': current_activity,
            'api_list': sens_api_name_list,
            'is_stuck': is_stuck,
            'recovered': recovered,
            'xml_score': float(xml_score),
            'img_same': bool(img_same),
            'reward_debug': f"api:{r_api}|exp:{r_exp}|wid:{r_wid}|pen:{r_pen}",
            'input_performed': bool(input_performed),
        }

        logger.info(
            f"Step {self.timesteps} | Reward: {reward:6.2f} | "
            f"Breakdown: [API:{r_api:5.1f}, Exp:{r_exp:5.1f}, Wid:{r_wid:5.1f}, Pen:{r_pen:5.1f}] | "
            f"APIs: {len(sens_api_name_list)} | Stuck: {is_stuck} | "
            f"xml:{xml_score:.3f} | img_same:{img_same} | Recovered: {recovered}"
        )

        return self.observation, reward, self._termination(), info

    def perform_adb_input(self, operatable_widget, keyword, input_value):
        try:
            x = int((operatable_widget.bounds[0] + operatable_widget.bounds[2]) / 2)
            y = int((operatable_widget.bounds[1] + operatable_widget.bounds[3]) / 2)

            # 批量执行 ADB 命令
            commands = [
                f"input tap {x} {y}",  # 点击输入框
                "input keyevent KEYCODE_MOVE_END",  # 移动到末尾
                f"input text '{input_value}'",  # 输入文本
                "input keyevent KEYCODE_BACK"  # 关闭键盘
            ]

            for cmd in commands:
                self.dm.shell(cmd)
                time.sleep(0.1)  # 最小必要等待

            logger.info(f"✅ Batch input success: {input_value}")
            return True

        except Exception as e:
            logger.warning(f"❌ Batch input failed: {e}")
            return False

    def _close_keyboard(self):
        """关闭软键盘（多种方法）"""
        try:
            # 方法1: 使用 UIAutomator2 的内置方法
            try:
                self.dm.press("back")  # 按返回键关闭键盘
                time.sleep(0.2)
            except:
                pass

            # 方法2: 点击输入框外的区域
            try:
                # 点击屏幕顶部（通常是安全区域）
                self.dm.click(config.Device_resolution_x / 2, 100)
                time.sleep(0.2)
            except:
                pass

            # 方法3: 使用 ADB 命令
            try:
                self.dm.shell("input keyevent KEYCODE_BACK")
                time.sleep(0.2)
            except:
                pass

            logger.debug("✅ 键盘已关闭")
        except Exception as e:
            logger.debug(f"关闭键盘失败: {e}")

    def _try_submit_input(self):
        """尝试触发输入提交"""
        try:
            # 方法1: 按回车键
            self.dm.press("enter")
            time.sleep(0.3)

            # 方法2: 查找并点击"搜索"、"确定"、"提交"等按钮
            submit_keywords = ['搜索', '确定', '提交', '发送', 'search', 'submit', 'send', 'ok']

            for widget_id in self.usable_widgets:
                widget = self.all_widget_dict.get(widget_id)
                if widget:
                    text = str(widget.text).lower()
                    res_id = str(widget.resource_id).lower()

                    if any(kw in text or kw in res_id for kw in submit_keywords):
                        # 找到提交按钮，点击它
                        x = (widget.bounds[0] + widget.bounds[2]) / 2
                        y = (widget.bounds[1] + widget.bounds[3]) / 2
                        self.dm.click(x, y)
                        logger.info(f"✅ 点击提交按钮: {widget.text}")
                        time.sleep(0.5)
                        break
        except Exception as e:
            logger.debug(f"提交输入失败: {e}")

    def perform_touch_action(self, operatable_widget):
        """执行触摸动作"""
        x = (operatable_widget.bounds[0] + operatable_widget.bounds[2]) / 2
        y = (operatable_widget.bounds[1] + operatable_widget.bounds[3]) / 2

        try:
            if operatable_widget.operatable == 1:
                self.dm.click(x, y)
                logger.info(f'Fast Click: ({x}, {y})')

            elif operatable_widget.operatable == 2:
                start_y = operatable_widget.bounds[3] - 100
                end_y = operatable_widget.bounds[1] + 100
                self.dm.swipe(x, start_y, x, end_y, duration=0.15)  # ✅ 减少滑动时间
                logger.info(f'Fast Swipe: ({x}, {start_y}) -> ({x}, {end_y})')

        except Exception as e:
            logger.error(f"Touch failed: {e}")
            self._fallback_touch(operatable_widget)

    def _fallback_touch(self, operatable_widget):
        """备选触摸方案"""
        try:
            pixel_bounds = operatable_widget.bounds
            x = int((pixel_bounds[0] + pixel_bounds[2]) / 2)
            y = int((pixel_bounds[1] + pixel_bounds[3]) / 2)

            if operatable_widget.operatable == 1:
                self.dm.click(x, y)
            elif operatable_widget.operatable == 2:
                start_y = int(pixel_bounds[3]) - 100
                end_y = int(pixel_bounds[1]) + 100
                self.dm.swipe(x, start_y, x, end_y, duration=0.3)
        except Exception as e:
            logger.error(f"Fallback touch also failed: {e}")

    def compute_reward(self):
        """计算奖励（备用方法）"""
        if self.executed_widget is None or len(self.next_widgets) == 0:
            return 0
        unvisited_widgets_num = len(self.next_widgets)
        return np.clip(unvisited_widgets_num, 0, 20, dtype=np.float32)

    def _termination(self):
        """判断是否终止"""
        if not self.monitoring_thread.is_alive():
            logger.warning("Monitoring thread died, terminating episode.")
            return True

        if self.un_variable_num >= 10:
            logger.info("Episode terminated: App trapped in an unvariable state.")
            return True

        return False

    def reset(self):
        self.timesteps = 0
        self.un_variable_num = 0
        self.seen_state_api_pairs.clear()

        # 1) 强 reset：清顶并重启 activity
        try:
            self.dm.shell(
                f"am start -S --activity-clear-top -n {self.appPackage}/{self.appActivity}"
            )
        except Exception:
            pass
        if not self._wait_for_app_ready(max_wait=5):
            try:
                self.dm.app_stop(self.appPackage)
                time.sleep(1.5)
                self.dm.app_start(self.appPackage)
            except Exception:
                pass
        # 最终兜底
        if not self._wait_for_app_ready(max_wait=5):
            start_activity(self.appPackage + '/' + self.appActivity)
        self.refreshNewObservation()
        return self.observation

    def clear(self):
        """清除状态"""
        self.executed_widget = None
        self.GUI_dict = set()
        self.all_widget_dict = {}
        self.current_activity = None
        self.observation = None
        self.un_variable_num = 0
        config.api_trigged_list.clear()

    def reset_for_new_episode(self):
        """每个 Episode 开始前调用，重置局部计数器"""
        self.un_variable_num = 0
        self.seen_state_api_pairs.clear()

        for widget in self.all_widget_dict.values():
            widget.visitCount = 0
            widget.shallow_visitCount = 0
        logger.info("Environment local counters reset for new episode.")

    def close(self):
        """关闭环境，清理资源"""
        # 停止异步保存线程
        self._save_queue.put(None)
        if self._save_thread.is_alive():
            self._save_thread.join(timeout=2)

        # 关闭线程池
        self._ui_executor.shutdown(wait=False)

        logger.info("✅ Environment closed.")

    def __del__(self):
        """析构函数，确保资源被清理"""
        try:
            self.close()
        except:
            pass

    def _wait_for_ui_change(self, old_signature, max_wait=2.0, check_interval=0.2):
        start = time.time()
        while time.time() - start < max_wait:
            try:
                xml = self.dm.safe_dump_hierarchy(compressed=True)
                if not xml:
                    time.sleep(check_interval)
                    continue
                new_sig = self._build_structure_signature(xml)
                if new_sig and new_sig != old_signature:
                    return xml
            except Exception:
                pass
            time.sleep(check_interval)
        return None

    def _make_state_id(self, xml_str, activity_name):
        if not xml_str:
            return "empty"
        signature = self._build_structure_signature(xml_str)
        final_str = f"{activity_name}_{signature}"
        return hashlib.md5(final_str.encode("utf-8")).hexdigest()

    def _get_state_id_fast(self):
        try:
            app_info = self.dm.app_current() or {}
            activity = app_info.get("activity", "unknown_activity")
            xml = self.dm.safe_dump_hierarchy(compressed=True)
            if not xml:
                return None
            return self._make_state_id(xml, activity)
        except Exception:
            return None