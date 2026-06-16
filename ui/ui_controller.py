import os
import sys
import json
import copy
import re
import subprocess
import pandas as pd
from fuzzywuzzy import fuzz

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTabWidget, QProgressBar,
    QGroupBox, QGridLayout, QMessageBox, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit,
    QListWidget, QListWidgetItem, QApplication, QAbstractItemView,
    QDialog, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

# 导入功能模块
from privacy_policy_analyzer import PrivacyPolicyAnalyzer
from app_behavior_analyzer import AppBehaviorAnalyzer
from compliance_checker import ComplianceChecker

import os
import json
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from PyQt5.QtWidgets import QShortcut
from PyQt5.QtGui import QKeySequence
class AnalysisThread(QThread):
    """后台分析线程"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    log_received = pyqtSignal(str)

    def __init__(self, apk_path, html_path):
        super().__init__()
        self.apk_path = apk_path
        self.html_path = html_path

        if self.html_path:
            folder_name = os.path.splitext(os.path.basename(self.html_path))[0]
        elif self.apk_path:
            folder_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        else:
            folder_name = "analysis_result"
        self.output_dir = os.path.join("result", folder_name)

    def run(self):
        try:
            results = {
                'policy': {},
                'static': {},
                'dynamic': {},
                'behavior': {},
                'compliance': {},
                'analysis_status': {'policy': False, 'static': False, 'dynamic': False},
            }
            ui_dir = os.path.dirname(os.path.abspath(__file__))
            default_config_path = os.path.join(ui_dir, "config.json")
            legacy_config_path = os.path.join(ui_dir, "privacy_analyzer_config.json")
            config_path = (
                os.getenv("UI_CONFIG")
                or os.getenv("PRIVACY_ANALYZER_CONFIG")
                or (
                    default_config_path
                    if os.path.exists(default_config_path) or not os.path.exists(legacy_config_path)
                    else legacy_config_path
                )
            )
            config = (
                PrivacyPolicyAnalyzer.load_config(config_path)
                if os.path.exists(config_path)
                else PrivacyPolicyAnalyzer.default_config()
            )

            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            def analyze_policy():
                if not self.html_path:
                    results['policy'] = {}
                    return
                self.progress.emit(10, "正在分析隐私政策...")
                policy_analyzer = PrivacyPolicyAnalyzer(self.html_path, self.output_dir)
                results['policy'] = policy_analyzer.analyze(config) or {}
                results['analysis_status']['policy'] = bool(results['policy'])
                self.progress.emit(40, "隐私政策分析完成")

            behavior_analyzer = None

            def get_behavior_analyzer():
                nonlocal behavior_analyzer
                if not self.apk_path:
                    return None
                if behavior_analyzer is None:
                    explorer_config = config.get("dynamic_explorer", {})
                    selected_algo = explorer_config.get("algo", "sac")
                    behavior_analyzer = AppBehaviorAnalyzer(self.apk_path, algo=selected_algo)
                return behavior_analyzer

            def refresh_behavior_result():
                analyzer = get_behavior_analyzer()
                if analyzer is None:
                    results['behavior'] = {}
                    return
                results['behavior'] = analyzer.merge_results(results.get('static'), results.get('dynamic'))

            def analyze_static():
                analyzer = get_behavior_analyzer()
                if analyzer is None:
                    results['static'] = {}
                    return
                self.progress.emit(35, "正在执行应用静态分析...")
                results['static'] = analyzer.analyze_static() or {}
                results['analysis_status']['static'] = bool(
                    results['static'].get('from_cache')
                    or results['static'].get('permissions')
                    or results['static'].get('static_apis')
                    or results['static'].get('package_name')
                )
                if results['static'].get('from_cache'):
                    self.log_received.emit("检测到静态分析缓存，已作为静态分析结果使用。")
                refresh_behavior_result()
                self.progress.emit(45, "应用静态分析完成")

            def analyze_dynamic():
                analyzer = get_behavior_analyzer()
                if analyzer is None:
                    results['dynamic'] = {}
                    return
                explorer_config = config.get("dynamic_explorer", {})
                script_path = explorer_config.get("script_path") or r"G:\iie\mylab\guitest\Explorer\explore33.py"
                script_dir = os.path.dirname(script_path)
                selected_algo = explorer_config.get("algo", "sac")
                cached_leak_path = analyzer.find_privacy_result_path()

                def run_logged_process(cmd, cwd, finished_message):
                    current_env = os.environ.copy()
                    current_env["PYTHONUNBUFFERED"] = "1"

                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding='utf-8',
                        errors='replace',
                        cwd=cwd,
                        env=current_env
                    )

                    while True:
                        line = process.stdout.readline()
                        if not line:
                            if process.poll() is not None:
                                break
                            continue
                        clean_line = line.strip()
                        if clean_line:
                            self.log_received.emit(clean_line)

                    process.stdout.close()
                    return_code = process.wait()
                    self.log_received.emit(finished_message)
                    return return_code

                def run_captured_process(cmd, cwd, finished_message, timeout_sec=None):
                    current_env = os.environ.copy()
                    current_env["PYTHONUNBUFFERED"] = "1"
                    try:
                        completed = subprocess.run(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            cwd=cwd,
                            env=current_env,
                            timeout=timeout_sec,
                        )
                        for line in (completed.stdout or "").splitlines():
                            clean_line = line.strip()
                            if clean_line:
                                self.log_received.emit(clean_line)
                        self.log_received.emit(finished_message)
                        return completed.returncode
                    except subprocess.TimeoutExpired as e:
                        output = e.stdout or ""
                        if isinstance(output, bytes):
                            output = output.decode("utf-8", errors="replace")
                        for line in output.splitlines():
                            clean_line = line.strip()
                            if clean_line:
                                self.log_received.emit(clean_line)
                        self.log_received.emit(f"汇总分析超过 {timeout_sec} 秒，已停止等待。")
                        return -1

                if cached_leak_path:
                    self.progress.emit(75, "检测到动态分析缓存，正在直接加载行为结果...")
                    self.log_received.emit(f"检测到动态分析缓存，跳过沙箱: {cached_leak_path}")
                else:
                    self.progress.emit(50, "未检测到动态分析缓存，正在启动动态沙箱...")

                    cmd = [
                        sys.executable, "-u", script_path,
                        "--apps", self.apk_path,
                        "--algo", selected_algo,
                    ]
                    explorer_arg_map = {
                        "apps_explored": "--apps_explored",
                        "iterations": "--iterations",
                        "episods": "--episods",
                        "stage": "--stage",
                        "platform_version": "--platform_version",
                        "udid": "--udid",
                        "device_name": "--device_name",
                        "layout_model": "--layout_model",
                        "memory_capacity": "--memory_capacity",
                        "num_actions": "--num_actions",
                    }
                    for config_key, cli_arg in explorer_arg_map.items():
                        value = explorer_config.get(config_key)
                        if value is not None and value != "":
                            cmd.extend([cli_arg, str(value)])

                    explorer_return_code = run_logged_process(cmd, script_dir, "动态探索进程已结束。")
                    if explorer_return_code != 0:
                        self.log_received.emit(f"动态探索进程返回非零状态码: {explorer_return_code}")

                cached_leak_path = analyzer.find_privacy_result_path()
                if not cached_leak_path and explorer_config.get("run_leak_analysis", True):
                    self.progress.emit(78, "正在生成 leak.json 行为证据...")
                    analysis_root = os.path.join(script_dir, "analysis")
                    leak_analyzer_script = explorer_config.get("leak_analyzer_script") or os.path.join(script_dir, "anal5.py")
                    leak_cmd = [
                        sys.executable, "-u", leak_analyzer_script,
                        "--path", os.path.join(analysis_root, selected_algo),
                        "--app", analyzer.app_name,
                        "--sdk-info", os.path.join(analysis_root, "sdk_info.json"),
                        "--device-info", os.path.join(analysis_root, "device_info.json"),
                    ]
                    leak_timeout = explorer_config.get("leak_analysis_timeout_sec", 300)
                    leak_return_code = run_captured_process(
                        leak_cmd,
                        script_dir,
                        "leak.json 汇总分析进程已结束。",
                        timeout_sec=leak_timeout,
                    )
                    if leak_return_code != 0:
                        self.log_received.emit(f"leak.json 汇总分析返回非零状态码: {leak_return_code}")

                self.progress.emit(80, "动态分析完成，正在汇总行为报告...")
                cached_leak_path = analyzer.find_privacy_result_path()
                if cached_leak_path:
                    self.log_received.emit(f"正在加载动态行为证据: {cached_leak_path}")
                else:
                    self.log_received.emit("未找到 leak.json，动态分析不能作为违规检测输入。")
                results['dynamic'] = analyzer.analyze_dynamic() or {}
                results['analysis_status']['dynamic'] = bool(results['dynamic'].get('leak_data'))
                refresh_behavior_result()
                self.progress.emit(85, "动态分析汇总完成")

            configured_order = config.get("ui", {}).get("analysis_order", ["policy", "static", "dynamic"])
            if isinstance(configured_order, str):
                configured_order = [configured_order]
            enabled_steps = []
            for step in configured_order:
                if step == "behavior":
                    step = "dynamic"
                if step in {"policy", "static", "dynamic"} and step not in enabled_steps:
                    enabled_steps.append(step)
            for step in ("policy", "static", "dynamic"):
                if step not in enabled_steps:
                    enabled_steps.append(step)

            analyzers = {
                "policy": analyze_policy,
                "static": analyze_static,
                "dynamic": analyze_dynamic,
            }
            for step in enabled_steps:
                analyzers[step]()

            self.progress.emit(90, "正在生成综合评估...")
            status = results.get('analysis_status', {})
            if status.get('policy') and status.get('static') and status.get('dynamic'):
                compliance_checker = ComplianceChecker()
                results['compliance'] = compliance_checker.check(
                    results.get('policy', {}),
                    results.get('behavior', {})
                )
            else:
                missing = [
                    name for key, name in (
                        ('policy', '隐私政策分析'),
                        ('static', '应用静态分析'),
                        ('dynamic', '动态沙箱分析'),
                    )
                    if not status.get(key)
                ]
                results['compliance'] = {
                    'skipped': True,
                    'missing_steps': missing,
                    'message': f"违规检测需等待三项分析全部完成，当前缺少：{'、'.join(missing)}",
                }

            self.progress.emit(100, "检测完成")
            self.finished.emit(results)

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            self.error.emit(f"分析过程出错: {str(e)}")


class PrivacyComplianceUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.apk_path = None
        self.html_path = None
        self.analysis_thread = None
        self.analysis_running = False
        self.compliance_rule_details = {}

        self.clause_hierarchy = self._load_clause_hierarchy("../../../lab8/ui/res/idlable.csv")
        self.data_categories = self._load_data_categories("G:/iie/mylab/guitest/Explorer/analysis/it_info.json")
        self.cache_dir = Path("./cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.clause_hierarchy_rows = [
            ("A1 处理者", "A2 身份", ""),
            ("A1 处理者", "A3 联系方式", ""),
            ("B1 个人信息保护负责人", "B2 联系方式", ""),
            ("C1 个人信息收集与使用", "C2 处理的个人信息类别", "C3 敏感个人信息"),
            ("C1 个人信息收集与使用", "C4 个人信息来源", "C5 直接主动"),
            ("C1 个人信息收集与使用", "C4 个人信息来源", "C6 直接被动"),
            ("C1 个人信息收集与使用", "C4 个人信息来源", "C7 间接"),
            ("C1 个人信息收集与使用", "C8 处理目的", ""),
            ("C1 个人信息收集与使用", "C9 处理方式", ""),
            ("C1 个人信息收集与使用", "C10 敏感信息处理", ""),
            ("C1 个人信息收集与使用", "C11 合法依据", "C12 个人同意"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C13 合同必需"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C14 法定义务"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C15 重大事件"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C16 公共利益"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C17 公开信息"),
            ("C1 个人信息收集与使用", "C11 合法依据", "C18 其他法规要求"),
            ("D1 个人信息分享", "D2 接收方", ""),
            ("D1 个人信息分享", "D3 情形", "D4 委托处理"),
            ("D1 个人信息分享", "D3 情形", "D5 合并分立"),
            ("D1 个人信息分享", "D3 情形", "D6 个人单独同意"),
            ("E1 数据主体权利", "E2 知情权", "E3 政策更新"),
            ("E1 数据主体权利", "E2 知情权", "E4 数据泄露通知"),
            ("E1 数据主体权利", "E2 知情权", "E5 其他"),
            ("E1 数据主体权利", "E6 获取权", ""),
            ("E1 数据主体权利", "E7 修改权", ""),
            ("E1 数据主体权利", "E8 删除权", ""),
            ("E1 数据主体权利", "E9 拒绝权", ""),
            ("E1 数据主体权利", "E10 自动决策权", ""),
            ("E1 数据主体权利", "E11 撤回同意权", ""),
            ("F1 投诉", "F2 响应时间", ""),
            ("F1 投诉", "F3 拒绝情形", ""),
            ("G1 个人信息处理原则", "", ""),
            ("H1 个人信息跨境传输", "H2 情形", ""),
            ("I1 数据存储细节", "I2 存储时长", ""),
            ("I1 数据存储细节", "I3 存储地点", ""),
            ("I1 数据存储细节", "I4 处理方法", ""),
            ("J1 个人信息安全", "", ""),
            ("K1 未成年人信息", "", ""),
            ("L1 非个保法要求", "L2 COOKIES", ""),
            #("M1 其他", "", "")
        ]
        self.init_ui()
        self.screenshot_dir = Path("./screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.init_screenshot_shortcut()

    def init_screenshot_shortcut(self):
        self.screenshot_shortcut = QShortcut(QKeySequence("Ctrl+M"), self)
        self.screenshot_shortcut.activated.connect(self.save_current_window_screenshot)

    def save_current_window_screenshot(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        current_tab_name = "main"

        central = self.centralWidget()
        if central is not None:
            tab_widget = central.findChild(QTabWidget)
            if tab_widget is not None:
                current_tab_name = tab_widget.tabText(tab_widget.currentIndex())

        safe_tab_name = re.sub(r'[\\/*?:"<>|]', "_", current_tab_name)
        save_path = self.screenshot_dir / f"{safe_tab_name}_{timestamp}.png"

        pixmap = self.grab()
        ok = pixmap.save(str(save_path), "PNG")

        if ok:
            self.statusBar().showMessage(f"截图已保存: {save_path}", 5000)
        else:
            QMessageBox.warning(self, "截图失败", "PNG 保存失败")

    def _load_data_categories(self, json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                categories = json.load(f)
            reverse_map = {}
            for category, items in categories.items():
                for item in items:
                    reverse_map[item.lower().strip()] = category
            return reverse_map
        except Exception as e:
            print(f"加载数据分类失败: {e}")
            return {}

    def _load_clause_hierarchy(self, csv_path):
        hierarchy = []
        try:
            df = pd.read_csv(csv_path)

            def get_depth(item_id):
                return len(str(item_id).split('.'))

            def find_parent(items, id_parts):
                parent_id = ".".join(id_parts[:-1])
                for item in items:
                    if str(item['id']) == parent_id:
                        item.setdefault('children', [])
                        return item['children']
                    if 'children' in item:
                        result = find_parent(item['children'], id_parts)
                        if result is not None:
                            return result
                return None

            for _, row in df.iterrows():
                clause_id = str(row['id'])
                clause_name = row['name']
                depth = get_depth(clause_id)
                id_parts = clause_id.split('.')
                new_item = {'id': clause_id, 'name': clause_name, 'status': '缺失'}

                if depth == 1:
                    hierarchy.append(new_item)
                else:
                    parent_list = find_parent(hierarchy, id_parts)
                    if parent_list is not None:
                        parent_list.append(new_item)
            return hierarchy
        except Exception as e:
            print(f"加载条款体系失败: {e}")
            return []

    def init_ui(self):
        self.setWindowTitle("安卓应用隐私违规泄露细粒度检测系统")
        self.setGeometry(100, 100, 1200, 800)

        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(16, 16, 16, 16)

        top_controls_layout = QHBoxLayout()
        top_controls_layout.setSpacing(15)
        upload_widget = self.create_upload_section()
        top_controls_layout.addWidget(upload_widget, 1)
        button_widget = self.create_button_section()
        top_controls_layout.addWidget(button_widget, 0, Qt.AlignVCenter)
        main_layout.addLayout(top_controls_layout)

        main_layout.addWidget(self.create_progress_section())
        main_layout.addWidget(self.create_tabs_section(), 1)

        central.setLayout(main_layout)

        self.apply_styles()
        self._apply_dpi_safe_sizes()

    def _apply_dpi_safe_sizes(self):
        btn_h = self.analyze_btn.fontMetrics().height() + 22
        self.analyze_btn.setMinimumHeight(btn_h)
        self.reset_btn.setMinimumHeight(btn_h)

        path_h = self.apk_path_label.fontMetrics().height() + 14
        self.apk_path_label.setMinimumHeight(path_h)
        self.html_path_label.setMinimumHeight(path_h)

    def _init_table(self, table: QTableWidget, headers):
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)

    def _add_table_row(self, table: QTableWidget, values):
        row = table.rowCount()
        table.insertRow(row)
        for col, val in enumerate(values):
            if col >= table.columnCount():
                break
            item = QTableWidgetItem("" if val is None else str(val))
            table.setItem(row, col, item)
        return row

    def create_upload_section(self):
        group = QGroupBox("文件上传")
        group.setObjectName("uploadGroup")

        layout = QGridLayout()
        layout.setSpacing(10)
        layout.setColumnStretch(1, 1)

        layout.addWidget(QLabel("APK文件:"), 0, 0)
        self.apk_path_label = QLabel("未选择文件")
        self.apk_path_label.setObjectName("pathLabel")
        self.apk_path_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(self.apk_path_label, 0, 1)

        self.apk_btn = QPushButton("选择APK")
        self.apk_btn.setObjectName("apkButton")
        self.apk_btn.clicked.connect(self.select_apk)
        layout.addWidget(self.apk_btn, 0, 2)

        layout.addWidget(QLabel("隐私政策:"), 1, 0)
        self.html_path_label = QLabel("未选择文件")
        self.html_path_label.setObjectName("pathLabel")
        self.html_path_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(self.html_path_label, 1, 1)

        self.html_btn = QPushButton("选择HTML")
        self.html_btn.setObjectName("htmlButton")
        self.html_btn.clicked.connect(self.select_html)
        layout.addWidget(self.html_btn, 1, 2)

        group.setLayout(layout)
        return group

    def create_button_section(self):
        """创建按钮区域：开始检测 + 重置 竖向组合，并与文件上传区域垂直对齐"""
        widget = QWidget()
        widget.setMinimumWidth(190)
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        # 上下加弹簧，让按钮组在右侧区域垂直居中（与文件上传块更对齐）
        outer_layout.addStretch(1)
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(10)
        self.analyze_btn = QPushButton('开始检测')
        self.analyze_btn.setObjectName("analyzeButton")
        self.analyze_btn.setMinimumWidth(170)
        self.analyze_btn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        btn_layout.addWidget(self.analyze_btn)
        self.reset_btn = QPushButton('重置')
        self.reset_btn.setObjectName("resetButton")
        self.reset_btn.setMinimumWidth(170)
        self.reset_btn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.reset_btn.clicked.connect(self.reset_form)
        btn_layout.addWidget(self.reset_btn)
        outer_layout.addLayout(btn_layout)
        outer_layout.addStretch(1)
        widget.setLayout(outer_layout)
        return widget

    def create_progress_section(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(4)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setVisible(False)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        widget.setLayout(layout)
        return widget

    def create_tabs_section(self):
        tabs = QTabWidget()
        tabs.addTab(self.create_policy_page(), "隐私政策检测")
        tabs.addTab(self.create_behavior_page(), "应用静态分析")
        tabs.addTab(self.create_dynamic_page(), "应用动态分析")
        tabs.addTab(self.create_compliance_page(), "综合结果")
        return tabs

    def create_policy_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        self.policy_empty_label = QLabel("等待上传文件并开始检测")
        self.policy_empty_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.policy_empty_label)

        self.policy_tabs = QTabWidget()
        self.policy_tabs.setVisible(False)

        tab1 = QWidget()
        tab1_layout = QVBoxLayout()
        self.policy_summary_label = QLabel("摘要：-")
        tab1_layout.addWidget(self.policy_summary_label)
        # 这里改成三级层级展示
        self.classification_table = QTableWidget()
        self._init_table(self.classification_table, ["第一层级", "第二层级", "第三层级", "覆盖情况"])
        tab1_layout.addWidget(self.classification_table)
        tab1.setLayout(tab1_layout)

        tab2 = QWidget()
        tab2_layout = QVBoxLayout()
        self.entity_summary_label = QLabel("结构化提取结果")
        tab2_layout.addWidget(self.entity_summary_label)
        self.entity_table = QTableWidget()
        self._init_table(self.entity_table, ["行为类型", "分类类别", "核心数据项", "处理目的/语境"])
        tab2_layout.addWidget(self.entity_table)
        tab2.setLayout(tab2_layout)

        self.policy_tabs.addTab(tab1, "条款合规概览")
        self.policy_tabs.addTab(tab2, "行为结构化提取")
        layout.addWidget(self.policy_tabs, 1)

        page.setLayout(layout)
        return page

    def create_behavior_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        self.behavior_empty_label = QLabel("等待上传 APK 文件以加载静态分析数据")
        self.behavior_empty_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.behavior_empty_label)

        self.behavior_tabs = QTabWidget()
        self.behavior_tabs.setVisible(False)

        perm_tab = QWidget()
        perm_layout = QVBoxLayout()
        self.behavior_summary_label = QLabel("静态权限信息")
        perm_layout.addWidget(self.behavior_summary_label)
        self.static_permission_table = QTableWidget()
        self._init_table(self.static_permission_table, ["权限名称"])
        perm_layout.addWidget(self.static_permission_table)
        perm_tab.setLayout(perm_layout)

        api_tab = QWidget()
        api_layout = QVBoxLayout()
        api_layout.addWidget(QLabel("静态检测敏感API列表"))
        self.static_api_list = QListWidget()
        api_layout.addWidget(self.static_api_list)
        api_tab.setLayout(api_layout)

        self.behavior_tabs.addTab(perm_tab, "权限声明列表")
        self.behavior_tabs.addTab(api_tab, "静态检测敏感API")
        layout.addWidget(self.behavior_tabs, 1)

        page.setLayout(layout)
        return page

    def create_dynamic_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        layout.addWidget(QLabel("动态分析日志"))

        self.dynamic_empty_label = QLabel("等待启动动态分析")
        self.dynamic_empty_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.dynamic_empty_label)

        self.dynamic_log_text = QPlainTextEdit()
        self.dynamic_log_text.setReadOnly(True)
        self.dynamic_log_text.setMaximumBlockCount(2000)
        self.dynamic_log_text.setVisible(False)
        layout.addWidget(self.dynamic_log_text, 1)

        page.setLayout(layout)
        return page

    def create_compliance_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        self.compliance_empty_label = QLabel("等待上传文件并开始检测")
        self.compliance_empty_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.compliance_empty_label)

        self.compliance_summary_label = QLabel("摘要：-")
        self.compliance_summary_label.setVisible(False)
        layout.addWidget(self.compliance_summary_label)

        self.compliance_table = QTableWidget()
        self._init_table(self.compliance_table, ["规则名称", "结果", "说明"])
        self.compliance_table.cellClicked.connect(self.show_compliance_rule_detail)
        self.compliance_table.setVisible(False)
        layout.addWidget(self.compliance_table, 1)

        page.setLayout(layout)
        return page

    def update_log_console(self, text):
        if not self.dynamic_log_text.isVisible():
            self.dynamic_log_text.setVisible(True)
            self.dynamic_empty_label.setVisible(False)
        self.dynamic_log_text.appendPlainText(text)
        sb = self.dynamic_log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def select_apk(self):
        if self.analysis_running:
            QMessageBox.warning(self, "提示", "分析正在进行中，请等待完成后再更换文件")
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择APK文件", "", "APK Files (*.apk);;All Files (*)"
        )
        if file_path:
            self.apk_path = file_path
            self.apk_path_label.setText(os.path.basename(file_path))
            self.apk_path_label.setToolTip(file_path)
            self.load_static_data_from_json(file_path)
            self.check_can_analyze()

    def select_html(self):
        if self.analysis_running:
            QMessageBox.warning(self, "提示", "分析正在进行中，请等待完成后再更换文件")
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择隐私政策HTML文件", "", "HTML Files (*.html *.htm);;All Files (*)"
        )
        if file_path:
            self.html_path = file_path
            self.html_path_label.setText(os.path.basename(file_path))
            self.html_path_label.setToolTip(file_path)
            self.check_can_analyze()

    def check_can_analyze(self):
        self.analyze_btn.setEnabled((not self.analysis_running) and bool(self.apk_path or self.html_path))

    def set_analysis_controls_enabled(self, enabled):
        self.analysis_running = not enabled
        self.analyze_btn.setEnabled(enabled and bool(self.apk_path or self.html_path))
        self.reset_btn.setEnabled(enabled)
        if hasattr(self, "apk_btn"):
            self.apk_btn.setEnabled(enabled)
        if hasattr(self, "html_btn"):
            self.html_btn.setEnabled(enabled)

    def clear_analysis_views(self, keep_static=False):
        self.policy_empty_label.setText("等待上传隐私政策文件以开始检测")
        self.policy_empty_label.setVisible(True)
        self.policy_tabs.setVisible(False)

        self.dynamic_empty_label.setVisible(True)
        self.dynamic_log_text.setVisible(False)
        self.dynamic_log_text.clear()

        self.compliance_empty_label.setVisible(True)
        self.compliance_summary_label.setVisible(False)
        self.compliance_table.setVisible(False)

        self.classification_table.setRowCount(0)
        self.entity_table.setRowCount(0)
        self.compliance_table.setRowCount(0)
        self.compliance_rule_details = {}

        self.policy_summary_label.setText("摘要：-")
        self.entity_summary_label.setText("结构化提取结果")
        self.compliance_summary_label.setText("摘要：-")

        if not keep_static:
            self.behavior_empty_label.setText("等待上传 APK 文件以加载静态分析数据")
            self.behavior_empty_label.setVisible(True)
            self.behavior_tabs.setVisible(False)
            self.static_permission_table.setRowCount(0)
            self.static_api_list.clear()
            self.behavior_summary_label.setText("静态权限信息")

    def start_analysis(self):
        if not self.apk_path and not self.html_path:
            QMessageBox.warning(self, "提示", "请至少上传APK文件或隐私政策文档")
            return
        if self.analysis_running or (self.analysis_thread and self.analysis_thread.isRunning()):
            QMessageBox.warning(self, "提示", "分析正在进行中，请勿重复操作")
            return

        self.set_analysis_controls_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setVisible(True)
        self.status_label.setText("准备开始检测")

        self.clear_analysis_views(keep_static=bool(self.apk_path))

        self.analysis_thread = AnalysisThread(self.apk_path, self.html_path)
        self.analysis_thread.log_received.connect(self.update_log_console)
        self.analysis_thread.progress.connect(self.update_progress)
        self.analysis_thread.finished.connect(self.display_results)
        self.analysis_thread.error.connect(self.show_error)
        self.analysis_thread.start()

    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def display_results(self, results):
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.set_analysis_controls_enabled(True)
        self.analysis_thread = None

        self.display_policy_results(results.get("policy", {}))
        self.display_behavior_results(results.get("behavior", {}))
        self.display_compliance_results(results.get("compliance", {}))

        QMessageBox.information(self, "完成", "检测已完成")

    def load_static_data_from_json(self, apk_path):
        package_name = os.path.splitext(os.path.basename(apk_path))[0]
        info_json_path = f"G:/iie/mylab/guitest/Explorer/apps/ap1/apinfo/{package_name}.json"
        hooks_json_path = f"G:/iie/mylab/guitest/Explorer/hooks/{package_name}.json"

        self.static_permission_table.setRowCount(0)
        self.static_api_list.clear()

        if os.path.exists(info_json_path):
            try:
                with open(info_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                perms = data.get("permissions", [])
                self.behavior_summary_label.setText(f"应用包名：{package_name}，检测到权限数：{len(perms)}")
                for p in perms:
                    self._add_table_row(self.static_permission_table, [p, "未知"])
            except Exception as e:
                self.behavior_summary_label.setText(f"读取权限文件失败：{e}")
        else:
            self.behavior_summary_label.setText(f"未找到权限配置文件：{info_json_path}")

        if os.path.exists(hooks_json_path):
            try:
                with open(hooks_json_path, 'r', encoding='utf-8') as f:
                    hooks_data = json.load(f)
                for item in hooks_data:
                    category = item.get("Category", "Unknown")
                    for hook in item.get("hooks", []):
                        clazz = hook.get("clazz", "")
                        method = hook.get("method", "")
                        self.static_api_list.addItem(QListWidgetItem(f"[{category}] {clazz}.{method}()"))
            except Exception as e:
                self.static_api_list.addItem(QListWidgetItem(f"读取 API 文件失败：{e}"))
        else:
            self.static_api_list.addItem(QListWidgetItem(f"未找到静态 API 配置文件：{hooks_json_path}"))

        self.behavior_empty_label.setVisible(False)
        self.behavior_tabs.setVisible(True)

    def create_behavior_section(self):
        group = QGroupBox("行为结构化提取")
        layout = QHBoxLayout()

        # 左侧：行为类型列表（可点击过滤）
        self.behavior_type_list = QListWidget()
        self.behavior_type_list.setMinimumWidth(180)
        self.behavior_type_list.itemClicked.connect(self.on_behavior_type_clicked)

        # 右侧：行为明细表
        self.behavior_table = QTableWidget()
        self.behavior_table.setColumnCount(4)
        self.behavior_table.setHorizontalHeaderLabels(["行为类型", "行为内容", "证据", "映射条款"])
        self.behavior_table.verticalHeader().setVisible(False)
        self.behavior_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.behavior_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.behavior_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.behavior_type_list, 0)
        layout.addWidget(self.behavior_table, 1)
        group.setLayout(layout)
        return group
    def display_policy_results(self, policy_data):
        if not policy_data:
            self.policy_empty_label.setText("未提供隐私政策文档，已跳过该项")
            self.policy_empty_label.setVisible(True)
            self.policy_tabs.setVisible(False)
            return

        self.policy_empty_label.setVisible(False)
        self.policy_tabs.setVisible(True)

        included_names = set(policy_data.get('keywords_found', []))
        missing_names = set(policy_data.get('missing_clauses', []))
        score = policy_data.get('score', 0)
        llm_entities_list = policy_data.get('llm_entities', [])

        def update_clause_status(clauses):
            for clause in clauses:
                clause_name = clause['name']
                has_children = 'children' in clause
                if has_children:
                    update_clause_status(clause['children'])

                is_included = clause_name in included_names
                is_missing = clause_name in missing_names

                if has_children:
                    child_statuses = [c['status'] for c in clause['children']]
                    if any(s == '已包含' for s in child_statuses) or is_included:
                        clause['status'] = '已包含'
                    else:
                        clause['status'] = '缺失'
                else:
                    clause['status'] = '已包含' if is_included else '缺失'

                if is_missing:
                    clause['status'] = '缺失'

        processed_hierarchy = copy.deepcopy(self.clause_hierarchy)
        update_clause_status(processed_hierarchy)

        allowed_labels = [
            '处理者', '联系方式', '个人信息保护负责人', '个人信息收集与使用', '处理的个人信息类别',
            '敏感个人信息', '个人信息来源', '直接主动', '直接被动', '间接', '处理目的', '个人信息分享',
            '接收方', '委托处理', '个人单独同意', '数据主体权利', '知情权', '政策更新', '数据泄露通知',
            '获取权', '修改权', '删除权', '转移权', '自动决策权', '撤回同意权', '死者个人信息权益',
            '投诉', '响应时间', '拒绝情形', '个人信息跨境传输', '数据存储细节', '存储时长', '存储地点',
            '个人信息安全', '未成年人信息', '非个保法要求', 'COOKIES'
        ]

        def flatten_clause_status(clauses, status_map):
            for clause in clauses:
                status_map[clause['name']] = clause.get('status', '缺失')
                if 'children' in clause:
                    flatten_clause_status(clause['children'], status_map)

        status_map = {}
        flatten_clause_status(processed_hierarchy, status_map)
        def label_name_only(text):
            if not text:
                return ""
            text = str(text).strip()
            return text.split(" ", 1)[1].strip() if " " in text else text

        def label_id_only(text):
            if not text:
                return ""
            text = str(text).strip()
            return text.split(" ", 1)[0].strip() if " " in text else text

        self.classification_table.setRowCount(0)

        # 表格按层级路径显示；状态按“最细层级标签”判断（l3优先，其次l2，再l1）
        for l1, l2, l3 in self.clause_hierarchy_rows:
            judge_name = label_name_only(l3) or label_name_only(l2) or label_name_only(l1)
            raw_status = status_map.get(judge_name, "缺失")      # 已包含 / 缺失
            show_status = "存在" if raw_status == "已包含" else "缺失"

            self._add_table_row(self.classification_table, [l1, l2, l3, show_status])
            row = self.classification_table.rowCount() - 1
            if show_status == "存在":
                row_bg = QColor("#E8F5E9")  # 淡绿
                row_fg = QColor("#1B5E20")
            else:
                row_bg = QColor("#FFEBEE")  # 淡红
                row_fg = QColor("#B71C1C")
            # 整行4列统一上色
            for c in range(4):
                item = self.classification_table.item(row, c)
                if item:
                    item.setBackground(row_bg)
                    item.setForeground(row_fg)

        # 摘要：按“每个标签节点(A1/A2/...)”统计，不按行统计
        unique_labels = {}  # id -> name
        for l1, l2, l3 in self.clause_hierarchy_rows:
            for txt in (l1, l2, l3):
                if not txt:
                    continue
                lid = label_id_only(txt)
                lname = label_name_only(txt)
                if lid and lid not in unique_labels:
                    unique_labels[lid] = lname

        exists_count = 0
        missing_count = 0
        for _, lname in unique_labels.items():
            st = status_map.get(lname, "缺失")
            if st == "已包含":
                exists_count += 1
            else:
                missing_count += 1

        self.policy_summary_label.setText(
            f"评分：{score}；标签总数：{len(unique_labels)}；存在：{exists_count}；缺失：{missing_count}"
        )

        data_categories_map = self.data_categories
        SIMILARITY_THRESHOLD = 85
        INVALID_TERMS = {"n/a", "na", "无", "暂无", "不适用"}
        GENERIC_DATA_TERMS = {"个人信息", "您的信息", "该部分隐私数据", "所指定的个人信息", "隐私数据", "信息"}
        SYNONYMS = {
            "设备平台": "平台", "设备厂商": "厂商", "设备品牌": "品牌", "设备型号": "型号",
            "设备识别码": "device id", "设备序列号": "sn", "交易金额信息": "金额", "支付订单号": "订单号",
            "通信/通话记录": "通话记录", "联系方式": "联系人", "人脸照片": "面部特征", "人脸照片数据": "面部特征",
            "特征码数据": "面部特征", "声码识别": "声纹", "cookie": "浏览记录", "名为cookie的小数据文件": "浏览记录",
            "账户信息": "其他账号", "昵称": "其他账号", "头像": "图片信息", "订单信息": "订单号",
            "交易": "消费记录", "支付": "消费记录", "消费记录": "消费记录", "物流信息": "访问日期",
        }
        STOPWORDS = ["该部分", "所指定", "个人", "您的", "隐私", "数据", "信息", "相关", "上述", "以上", "例如", "等", "内容"]

        def normalize_item_name(name: str) -> str:
            cleaned = (name or "").lower().strip()
            for w in STOPWORDS:
                cleaned = cleaned.replace(w, "")
            return re.sub(r"\s+", "", cleaned)

        def is_invalid_item(name: str) -> bool:
            return (name is None) or (name.strip().lower() in INVALID_TERMS)

        def classify_data_item(item_name, categories_map):
            if not categories_map or not item_name or is_invalid_item(item_name):
                return "未分类数据"

            raw = item_name.strip()
            parts = [p.strip() for p in re.split(r"[，,、/;；|]+", raw) if p.strip()]
            candidates = []
            for p in parts:
                if p in GENERIC_DATA_TERMS or is_invalid_item(p):
                    continue
                candidates.append(SYNONYMS.get(p, p))

            if not candidates:
                return "未分类数据"

            category_labels = set(categories_map.values())
            for c in candidates:
                if c in category_labels:
                    return c

            best_score = 0
            best_category = "未分类数据"
            for c in candidates:
                c_norm = normalize_item_name(c)
                if not c_norm:
                    continue
                for std_name, cat in categories_map.items():
                    s_norm = normalize_item_name(std_name)
                    if not s_norm:
                        continue
                    if c_norm == s_norm or c_norm in s_norm or s_norm in c_norm:
                        return cat
                    score_local = fuzz.token_set_ratio(c_norm, s_norm)
                    if score_local > best_score:
                        best_score = score_local
                        best_category = cat

            return best_category if best_score >= SIMILARITY_THRESHOLD else "未分类数据"

        self.entity_table.setRowCount(0)
        action_map = {"collection": "收集", "sharing": "共享", "other": "其他"}
        entity_count = 0

        for item in llm_entities_list:
            entities = item.get("entities", [])
            if not entities:
                continue

            action = "other"
            for e in entities:
                if e.get("label") in action_map:
                    action = e.get("label")
                    break

            raw_data_entities = [e.get("text", "") for e in entities if e.get("label") == "data"]
            filtered_data_entities = [
                t for t in raw_data_entities if t and t.strip() not in GENERIC_DATA_TERMS and t.strip().lower() not in {"n/a", "na"}
            ]
            data_display = "，".join(filtered_data_entities) if filtered_data_entities else "-"

            all_sub_items = []
            for raw_entity_str in raw_data_entities:
                clean_str = raw_entity_str.replace('，', ',').replace('、', ',').replace('；', ',').replace(';', ',')
                all_sub_items.extend([s.strip() for s in clean_str.split(',') if s.strip()])

            category_set = set()
            for sub in all_sub_items:
                cat = classify_data_item(sub, data_categories_map)
                if cat != "未分类数据":
                    category_set.add(cat)

            category_display = "，".join(sorted(category_set)) if category_set else "未分类数据"
            purpose = next((e.get("text", "-") for e in entities if e.get("label") in ["purpose", "condition"]), "-")

            row = self._add_table_row(
                self.entity_table,
                [action_map.get(action, "其他"), category_display, data_display, purpose]
            )
            entity_count += 1

            cat_item = self.entity_table.item(row, 1)
            if category_display == "未分类数据":
                if cat_item:
                    cat_item.setForeground(QColor("#C62828"))

        if entity_count == 0:
            self._add_table_row(self.entity_table, ["-", "-", "-", "未检测到结构化数据处理行为"])

        self.entity_summary_label.setText(f"结构化提取记录数：{entity_count}")

    def display_behavior_results(self, behavior_data):
        if not behavior_data:
            if self.apk_path:
                message = "未生成应用行为分析结果，请检查动态分析日志或缓存文件"
                self.behavior_summary_label.setText(message)
                self.behavior_empty_label.setText(message)
                self.behavior_empty_label.setVisible(not self.behavior_tabs.isVisible())
            return

        self.behavior_empty_label.setVisible(False)
        self.behavior_tabs.setVisible(True)

        permissions = behavior_data.get('permissions', [])
        risk_level = behavior_data.get('risk_level', '未知')
        risk_map = {"low": "低", "medium": "中", "high": "高"}
        risk_cn = risk_map.get(risk_level, str(risk_level))
        self.behavior_summary_label.setText(f"行为分析风险等级：{risk_cn}")

        self.static_permission_table.setRowCount(0)
        for p in permissions:
            name = p.get("name", "")
            level = p.get("level", "")
            row = self._add_table_row(self.static_permission_table, [name, level])

            level_item = self.static_permission_table.item(row, 1)
            if level_item:
                if level == "dangerous":
                    level_item.setForeground(QColor("#C62828"))
                else:
                    level_item.setForeground(QColor("#455A64"))

        self.static_api_list.clear()
        apis = behavior_data.get('static_apis') or behavior_data.get('sensitive_apis', [])
        if apis:
            for api in apis:
                self.static_api_list.addItem(QListWidgetItem(str(api)))
        else:
            self.static_api_list.addItem(QListWidgetItem("未检测到显著敏感API调用"))

    def display_compliance_results(self, compliance_data):
        if not compliance_data:
            self.compliance_empty_label.setVisible(True)
            self.compliance_table.setVisible(False)
            return

        if compliance_data.get("skipped"):
            self.compliance_empty_label.setText(compliance_data.get("message", "违规检测尚未执行"))
            self.compliance_empty_label.setVisible(True)
            self.compliance_summary_label.setVisible(False)
            self.compliance_table.setVisible(False)
            self.compliance_rule_details = {}
            return

        self.compliance_empty_label.setVisible(False)
        self.compliance_summary_label.setVisible(True)
        self.compliance_table.setVisible(True)
        self.compliance_table.setRowCount(0)

        policy_compliance = compliance_data.get('policy_compliance', {})
        rules_status = policy_compliance.get('rules_status', {})
        violations = policy_compliance.get('violations', [])
        self.compliance_rule_details = (
            policy_compliance.get("evidence", {}).get("rule_details", {}) or {}
        )

        # 定义 UI 显示的规则列表
        display_rules = [
            ("R1", "结构完整性缺失"),
            ("R2", "收集来源不透明"),
            ("R3", "存储生命周期缺失"),
            ("R4", "用户核心权利缺失"),
            ("R5", "政策更新机制缺失"),
            ("R6", "未经同意收集"),
            ("R7", "违规扩散"),
            ("R8", "模糊披露"),
        ]

        violated_count = 0
        for r_id, r_name in display_rules:
            status = rules_status.get(r_id, "合规")

            # 查找具体原因
            reason = "符合规范要求"
            if status == "违规":
                for v in violations:
                    if v['id'] == r_id:
                        reason = v['reason']
                        break
            elif r_id == "R6":
                reason = status
            elif r_id in ["R7", "R8"]:
                reason = "暂未检测到违规行为"
            if r_id in self.compliance_rule_details and not (r_id == "R6" and status == "合规"):
                reason = f"{reason}（点击查看动态证据）"

            # 添加到表格
            row_idx = self._add_table_row(self.compliance_table, [f"{r_id}-{r_name}", status, reason])
            for col in range(self.compliance_table.columnCount()):
                cell = self.compliance_table.item(row_idx, col)
                if cell:
                    cell.setData(Qt.UserRole, r_id)

            # 着色
            status_item = self.compliance_table.item(row_idx, 1)
            if status_item:
                if status == "违规":
                    status_item.setForeground(QColor("#C62828"))  # 红色
                    violated_count += 1
                else:
                    status_item.setForeground(QColor("#2E7D32"))  # 绿色
            elif status == "违规":
                violated_count += 1

        self.compliance_summary_label.setText(f"检测规则总数：{len(display_rules)}，发现违规项：{violated_count}")

    def show_compliance_rule_detail(self, row, column):
        rule_item = self.compliance_table.item(row, 0)
        if not rule_item:
            return
        rule_id = rule_item.data(Qt.UserRole) or rule_item.text().split("-", 1)[0]
        if rule_id not in {"R6", "R7", "R8"}:
            return

        detail = self.compliance_rule_details.get(rule_id)
        if not detail:
            QMessageBox.information(self, "规则详情", "当前规则没有可展示的动态证据。")
            return

        records_text = self._format_rule_records(detail.get("records", []))
        dialog = QDialog(self)
        dialog.setWindowTitle(detail.get("title", f"{rule_id} 规则详情"))
        dialog.resize(820, 520)

        layout = QVBoxLayout(dialog)
        summary = QLabel(detail.get("summary", "动态证据详情"))
        summary.setWordWrap(True)
        layout.addWidget(summary)

        evidence_text = QPlainTextEdit()
        evidence_text.setReadOnly(True)
        evidence_text.setPlainText(records_text or "无明细记录")
        layout.addWidget(evidence_text, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec_()

    @staticmethod
    def _format_rule_records(records):
        lines = []
        for idx, record in enumerate(records or [], start=1):
            lines.append(f"[{idx}]")
            if isinstance(record, dict):
                for key, value in record.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False, indent=2)
                    lines.append(f"{key}: {value}")
            else:
                lines.append(str(record))
            lines.append("")
        return "\n".join(lines).strip()
    # def display_compliance_results(self, compliance_data):
    #     if not compliance_data:
    #         self.compliance_empty_label.setText("未提供分析结果，无法生成合规报告")
    #         self.compliance_empty_label.setVisible(True)
    #         self.compliance_summary_label.setVisible(False)
    #         self.compliance_table.setVisible(False)
    #         return
    #
    #     self.compliance_empty_label.setVisible(False)
    #     self.compliance_summary_label.setVisible(True)
    #     self.compliance_table.setVisible(True)
    #     self.compliance_table.setRowCount(0)
    #
    #     policy_compliance = compliance_data.get('policy_compliance', {})
    #     if not policy_compliance and self.apk_path:
    #         self.compliance_summary_label.setText("仅完成应用行为核验，请上传隐私政策后再进行对标分析")
    #         return
    #
    #     missing_sections = policy_compliance.get('missing_sections', [])
    #     violations = policy_compliance.get('violations', [])
    #     warnings = policy_compliance.get('warnings', [])
    #
    #     def extract_rule_detail(prefix):
    #         for v in violations:
    #             if v.startswith(prefix):
    #                 return v
    #         for w in warnings:
    #             if w.startswith(prefix):
    #                 return w
    #         return ""
    #
    #     rules = [
    #         ("S1-结构完整性", "S1-"),
    #         ("B2-共享单独同意缺失", "B2-"),
    #         ("B6-敏感信息单独同意缺失", "B6-"),
    #         ("B8-收集来源不透明", "B8-"),
    #         ("H1-存储生命周期缺失", "H1-"),
    #         ("E-Core-核心权利束缺失", "E-Core-"),
    #         ("B5-第三方透明度不足", "B5-"),
    #         ("B1-投诉渠道不明确", "B1-"),
    #         ("G1-跨境传输风险", "G1-"),
    #         ("B4-权利限制告知缺失", "B4-"),
    #     ]
    #
    #     violated_count = 0
    #
    #     s1_detail = f"缺失章节: {', '.join(missing_sections)}" if missing_sections else "符合要求"
    #     s1_status = "违规" if missing_sections else "合规"
    #     self._add_table_row(self.compliance_table, ["S1-结构完整性", s1_status, s1_detail])
    #
    #     for i, (_, prefix) in enumerate(rules[1:], start=1):
    #         name = rules[i][0]
    #         detail = extract_rule_detail(prefix)
    #         status = "违规" if detail else "合规"
    #         info = detail if detail else "符合要求"
    #         self._add_table_row(self.compliance_table, [name, status, info])
    #
    #     for r in range(self.compliance_table.rowCount()):
    #         status_item = self.compliance_table.item(r, 1)
    #         if status_item.text() == "违规":
    #             status_item.setForeground(QColor("#C62828"))
    #             violated_count += 1
    #         else:
    #             status_item.setForeground(QColor("#2E7D32"))
    #
    #     total_rules = self.compliance_table.rowCount()
    #     self.compliance_summary_label.setText(f"规则总数：{total_rules}，违规项：{violated_count}")

    def show_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.set_analysis_controls_enabled(True)
        self.analysis_thread = None
        QMessageBox.critical(self, "错误", error_msg)

    def reset_form(self):
        if self.analysis_running or (self.analysis_thread and self.analysis_thread.isRunning()):
            QMessageBox.warning(self, "提示", "分析正在进行中，请等待完成后再重置")
            return
        self.apk_path = None
        self.html_path = None

        self.apk_path_label.setText("未选择文件")
        self.apk_path_label.setToolTip("")
        self.html_path_label.setText("未选择文件")
        self.html_path_label.setToolTip("")
        self.check_can_analyze()

        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        self.status_label.setVisible(False)
        self.status_label.setText("")

        self.clear_analysis_views(keep_static=False)

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background: #f3f4f6;
            }
            QGroupBox {
                background: #ffffff;
                border: 1px solid #d1d5db;
                margin-top: 8px;
                padding-top: 8px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QLabel#pathLabel {
                background: #ffffff;
                border: 1px solid #d1d5db;
                padding: 6px;
            }
            QPushButton {
                padding: 6px 14px;
                border: 1px solid transparent;
                border-radius: 4px;
                color: white;
                font-size: 13px;
            }
            
            /* 选择APK：低饱和绿 */
            QPushButton#apkButton {
                background-color: #5E8C61;   /* normal */
                border-color: #4F7752;
            }
            QPushButton#apkButton:hover {
                background-color: #527C55;   /* hover */
            }
            QPushButton#apkButton:pressed {
                background-color: #466A49;   /* pressed */
            }
            
            /* 选择HTML：低饱和蓝 */
            QPushButton#htmlButton {
                background-color: #4F78A6;
                border-color: #42658B;
            }
            QPushButton#htmlButton:hover {
                background-color: #456B95;
            }
            QPushButton#htmlButton:pressed {
                background-color: #3C5D80;
            }
            
            /* 开始检测：主按钮（蓝灰） */
            QPushButton#analyzeButton {
                background-color: #4B5D73;
                border-color: #3F4F62;
                font-weight: 600;
            }
            QPushButton#analyzeButton:hover {
                background-color: #425266;
            }
            QPushButton#analyzeButton:pressed {
                background-color: #384657;
            }
            QPushButton#analyzeButton:disabled {
                background-color: #A8B0BA;
                border-color: #9AA3AE;
                color: #F5F6F7;
            }
            
            /* 重置：低饱和棕橙 */
            QPushButton#resetButton {
                background-color: #A9794E;
                border-color: #916743;
            }
            QPushButton#resetButton:hover {
                background-color: #976C46;
            }
            QPushButton#resetButton:pressed {
                background-color: #825D3C;
            }
            QTabWidget::pane {
                border: 1px solid #d1d5db;
                background: #ffffff;
            }
            QTabBar::tab {
                background: #e5e7eb;
                padding: 8px 14px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                border: 1px solid #d1d5db;
                border-bottom: none;
            }
            QTableWidget, QPlainTextEdit, QListWidget {
                background: #ffffff;
                border: 1px solid #d1d5db;
                gridline-color: #e5e7eb;
            }
            QHeaderView::section {
                background: #f3f4f6;
                border: 1px solid #e5e7eb;
                padding: 4px;
            }
            QProgressBar {
                border: 1px solid #9ca3af;
                text-align: center;
                height: 24px;
            }
            QProgressBar::chunk {
                background: #4b5563;
            }
        """)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PrivacyComplianceUI()
    window.show()
    sys.exit(app.exec_())
