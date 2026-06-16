import os
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QFileDialog, QTextEdit,
                             QTabWidget, QProgressBar, QGroupBox, QGridLayout,
                             QMessageBox, QFrame, QApplication)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import sys
# 导入功能模块
from privacy_policy_analyzer import PrivacyPolicyAnalyzer
from app_behavior_analyzer import AppBehaviorAnalyzer
from compliance_checker import ComplianceChecker
from llm_extractor import LLMEntityExtractor
import subprocess
import os
from PyQt5.QtGui import QFont, QTextCursor

class AnalysisThread(QThread):
    """后台分析线程"""
    progress = pyqtSignal(int, str)  # 进度值, 进度描述
    finished = pyqtSignal(dict)  # 完成信号，携带结果
    error = pyqtSignal(str)  # 错误信号
    log_received = pyqtSignal(str)

    def __init__(self, apk_path, html_path):
        super().__init__()
        self.apk_path = apk_path
        self.html_path = html_path
        self.output_dir = "result"  # 确保 output_dir 被正确初始化


    def run(self):
        try:
            results = {}
            # 1. 基础配置
            config = {
                'model_path': r"G:\downloads\fromtencent\7.27\models\roberta-multilabel-classifier-d1-82-9575-05-V1\checkpoint-25685",
                'csv_label_path': "result/idlable.csv",
                'removed_ids': {6, 7, 8, 9, 10, 11},
                'thresholds_path': "result/optimal_thresholds.npy"
            }

            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)

            # 2. 隐私政策分析
            if self.html_path:
                self.progress.emit(10, "正在分析隐私政策...")
                policy_analyzer = PrivacyPolicyAnalyzer(self.html_path, self.output_dir)
                results['policy'] = policy_analyzer.analyze(config)
                self.progress.emit(40, "隐私政策分析完成")
            else:
                results['policy'] = {}

            # 3. 动态应用行为分析 (Explore3)
            if self.apk_path:
                self.progress.emit(50, "正在启动动态沙箱...")

                apk_dir = os.path.dirname(self.apk_path)
                # 使用 r"" 防止路径转义
                script_path = r"G:\iie\mylab\guitest\Explorer\explore3.py"
                script_dir = os.path.dirname(script_path)  # 获取脚本所在目录
                selected_algo="sac"
                # 构建指令，增加 -u 参数强制无缓存输出
                cmd = [
                    "python", "-u", script_path,
                    "--apps", apk_dir,
                    "--iterations", "50",
                    "--algo", selected_algo,
                ]

                # 增加 env 确保子进程知道自己要输出到控制台
                import os as os_module
                current_env = os_module.environ.copy()
                current_env["PYTHONUNBUFFERED"] = "1"

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # 必须合并
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    cwd=script_dir,
                    env=current_env  # 强制无缓存环境变量
                )

                # 改用更可靠的读取方式
                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    clean_line = line.strip()
                    if clean_line:
                        # print(f"Thread Debug: {clean_line}") # 调试打印
                        self.log_received.emit(clean_line)

                process.stdout.close()
                process.wait()
                self.log_received.emit(">>> 动态分析进程已结束。")

                self.progress.emit(80, "动态分析完成，正在汇总行为报告...")

                # 4. 汇总结果 (读取 pkl 等)
                behavior_analyzer = AppBehaviorAnalyzer(self.apk_path,selected_algo)
                results['behavior'] = behavior_analyzer.analyze()
                self.progress.emit(85, "应用行为分析汇总完成")
            else:
                results['behavior'] = {}

            # 5. 综合评估
            self.progress.emit(90, "正在生成综合评估...")
            compliance_checker = ComplianceChecker()
            results['compliance'] = compliance_checker.check(
                results.get('policy', {}),
                results.get('behavior', {})
            )
            self.progress.emit(100, "检测完成！")

            self.finished.emit(results)

        except Exception as e:
            import traceback
            error_details = traceback.format_exc()  # 获取详细堆栈信息
            print(error_details)
            self.error.emit(f"分析过程出错: {str(e)}")


class PrivacyComplianceUI(QMainWindow):
    """隐私合规检测系统主界面"""

    def __init__(self):
        super().__init__()
        self.apk_path = None
        self.html_path = None
        self.analysis_thread = None
        self.init_ui()

    def update_log_console(self, text):
        # 1. 收到日志时，强制显示控件，隐藏提示标签
        if not self.dynamic_result_text.isVisible():
            self.dynamic_result_text.setVisible(True)
            self.dynamic_empty_label.setVisible(False)

        # 2. 追加日志
        self.dynamic_result_text.append(text)

        # 3. 自动滚动到底部
        cursor = self.dynamic_result_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.dynamic_result_text.setTextCursor(cursor)

    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle('隐私合规检测系统 v1.0')
        self.setGeometry(100, 100, 1200, 800)

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # 标题栏
        title_widget = self.create_title_section()
        main_layout.addWidget(title_widget)

        # --- 新增的水平布局，用于放置文件上传和按钮 ---
        top_controls_layout = QHBoxLayout()
        top_controls_layout.setSpacing(15)  # 设置上传区域和按钮区域之间的间距

        # 文件上传区域
        upload_widget = self.create_upload_section()
        top_controls_layout.addWidget(upload_widget)  # 不添加拉伸因子，让它占据自然宽度


        # 按钮区域 (现在只包含按钮本身，不再有内部的拉伸)
        button_widget = self.create_button_section()
        top_controls_layout.addWidget(button_widget)  # 按钮部件占据其自然宽度

        # 将这个新的水平布局添加到主垂直布局中
        main_layout.addLayout(top_controls_layout)
        # --- 结束新增 ---

        # 进度条和状态 (位置不变)
        progress_widget = self.create_progress_section()
        main_layout.addWidget(progress_widget)

        # 功能页面区域（始终显示），并使其占据更多垂直空间
        self.tabs_widget = self.create_tabs_section()
        main_layout.addWidget(self.tabs_widget, 1)  # 关键：添加拉伸因子 1，使其占据剩余所有垂直空间

        central_widget.setLayout(main_layout)

        # 应用样式
        self.apply_styles()

    def create_title_section(self):
        """创建标题区域"""
        title_frame = QFrame()
        title_frame.setObjectName("titleFrame")
        title_layout = QVBoxLayout()

        title_label = QLabel('隐私合规检测系统')
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setObjectName("mainTitle")  # 这个ID用于CSS样式
        title_layout.addWidget(title_label)
        title_frame.setLayout(title_layout)

        return title_frame

    def create_upload_section(self):
        """创建文件上传区域"""
        group = QGroupBox("文件上传")
        group.setObjectName("uploadGroup")
        layout = QGridLayout()
        layout.setSpacing(15)
        layout.setColumnStretch(1, 1)

        # APK文件上传
        apk_label = QLabel('APK文件:')
        apk_label.setObjectName("fieldLabel")
        layout.addWidget(apk_label, 0, 0)

        self.apk_path_label = QLabel('未选择文件')
        self.apk_path_label.setObjectName("pathLabel")
        layout.addWidget(self.apk_path_label, 0, 1)

        apk_btn = QPushButton('选择APK')
        apk_btn.setObjectName("apkButton")
        apk_btn.clicked.connect(self.select_apk)
        layout.addWidget(apk_btn, 0, 2)

        # HTML文件上传
        html_label = QLabel('隐私政策:')
        html_label.setObjectName("fieldLabel")
        layout.addWidget(html_label, 1, 0)

        self.html_path_label = QLabel('未选择文件')
        self.html_path_label.setObjectName("pathLabel")
        layout.addWidget(self.html_path_label, 1, 1)

        html_btn = QPushButton('选择HTML')
        html_btn.setObjectName("htmlButton")
        html_btn.clicked.connect(self.select_html)
        layout.addWidget(html_btn, 1, 2)

        group.setLayout(layout)
        return group

    def create_progress_section(self):
        """创建进度显示区域"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(5)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)

        self.status_label = QLabel('')
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setObjectName("statusLabel")
        self.status_label.setVisible(False)

        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        widget.setLayout(layout)

        return widget

    def create_button_section(self):
        """创建按钮区域 - 调整为不包含弹性空间，仅包含按钮"""
        widget = QWidget()
        layout = QHBoxLayout()  # 保持水平布局，让两个按钮并排
        layout.setContentsMargins(0, 0, 0, 0)  # 移除默认边距，让按钮更紧凑
        layout.setSpacing(15)
        # 对齐方式：将按钮组在垂直方向上居中，在水平方向上（如果空间允许）靠右
        layout.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        # 移除原有的 layout.addStretch() 调用，因为外部布局会处理拉伸

        self.analyze_btn = QPushButton('开始检测')
        self.analyze_btn.setObjectName("analyzeButton")
        self.analyze_btn.setMinimumSize(150, 45)
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        layout.addWidget(self.analyze_btn)

        reset_btn = QPushButton('重置')
        reset_btn.setObjectName("resetButton")
        reset_btn.setMinimumSize(150, 45)
        reset_btn.clicked.connect(self.reset_form)
        layout.addWidget(reset_btn)

        widget.setLayout(layout)
        return widget

    def create_tabs_section(self):
        """创建功能页面标签（始终显示）"""
        tabs = QTabWidget()
        tabs.setObjectName("mainTabs")

        # 隐私政策检测页面
        self.policy_page = self.create_policy_page()
        tabs.addTab(self.policy_page, "隐私政策检测")

        # 应用行为分析页面
        self.behavior_page = self.create_behavior_page()
        tabs.addTab(self.behavior_page, "应用静态分析")
        # 应用动态分析页面

        self.dynamic_page = self.create_dynamic_page()
        tabs.addTab(self.dynamic_page, "应用动态分析")

        # 综合结果页面
        self.compliance_page = self.create_compliance_page()
        tabs.addTab(self.compliance_page, "综合结果")

        return tabs

    def create_policy_page(self):
        """创建隐私政策检测页面"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)


        # 提示信息
        self.policy_empty_label = QLabel('等待上传文件并开始检测...')
        self.policy_empty_label.setAlignment(Qt.AlignCenter)
        self.policy_empty_label.setObjectName("emptyLabel")
        layout.addWidget(self.policy_empty_label)

        # 结果显示区域
        self.policy_result_text = QTextEdit()
        self.policy_result_text.setReadOnly(True)
        self.policy_result_text.setObjectName("resultText")
        self.policy_result_text.setVisible(False)
        layout.addWidget(self.policy_result_text)

        page.setLayout(layout)
        return page

    def create_behavior_page(self):
        """创建应用行为分析页面"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)

        # 提示信息
        self.behavior_empty_label = QLabel('等待上传文件并开始检测...')
        self.behavior_empty_label.setAlignment(Qt.AlignCenter)
        self.behavior_empty_label.setObjectName("emptyLabel")
        layout.addWidget(self.behavior_empty_label)

        # 结果显示区域
        self.behavior_result_text = QTextEdit()
        self.behavior_result_text.setReadOnly(True)
        self.behavior_result_text.setObjectName("resultText")
        self.behavior_result_text.setVisible(False)
        layout.addWidget(self.behavior_result_text)

        page.setLayout(layout)
        return page

    def create_compliance_page(self):
        """创建综合结果页面"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)

        # 提示信息
        self.compliance_empty_label = QLabel('等待上传文件并开始检测...')
        self.compliance_empty_label.setAlignment(Qt.AlignCenter)
        self.compliance_empty_label.setObjectName("emptyLabel")
        layout.addWidget(self.compliance_empty_label)

        # 分数显示框
        score_frame = QFrame()
        score_frame.setObjectName("scoreFrame")
        score_frame.setVisible(False)
        score_layout = QVBoxLayout()

        self.score_label = QLabel('--')
        self.score_label.setAlignment(Qt.AlignCenter)
        self.score_label.setObjectName("scoreLabel")
        score_layout.addWidget(self.score_label)

        self.compliance_status_label = QLabel('等待检测')
        self.compliance_status_label.setAlignment(Qt.AlignCenter)
        self.compliance_status_label.setObjectName("complianceStatus")
        score_layout.addWidget(self.compliance_status_label)

        score_frame.setLayout(score_layout)
        self.score_frame = score_frame
        layout.addWidget(score_frame)

        # 详细结果
        self.compliance_result_text = QTextEdit()
        self.compliance_result_text.setReadOnly(True)
        self.compliance_result_text.setObjectName("resultText")
        self.compliance_result_text.setVisible(False)
        layout.addWidget(self.compliance_result_text)

        page.setLayout(layout)
        return page

    def create_dynamic_page(self):
        """创建应用动态分析页面"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)

        # 标题
        title = QLabel('应用动态分析结果 (沙箱运行)')
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        # 提示信息
        self.dynamic_empty_label = QLabel('等待启动动态沙箱并获取运行数据...')
        self.dynamic_empty_label.setAlignment(Qt.AlignCenter)
        self.dynamic_empty_label.setObjectName("emptyLabel")
        layout.addWidget(self.dynamic_empty_label)

        # 结果显示区域 (使用 QTextEdit 展示格式化的 HTML 内容)
        self.dynamic_result_text = QTextEdit()
        self.dynamic_result_text.setReadOnly(True)
        self.dynamic_result_text.setObjectName("resultText")
        self.dynamic_result_text.setVisible(False)
        layout.addWidget(self.dynamic_result_text)

        page.setLayout(layout)
        return page

    def select_apk(self):
        """选择APK文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择APK文件",
            "",
            "APK Files (*.apk);;All Files (*)"
        )
        if file_path:
            self.apk_path = file_path
            self.apk_path_label.setText(os.path.basename(file_path))
            self.apk_path_label.setToolTip(file_path)
            self.check_can_analyze()

    def select_html(self):
        """选择HTML文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择隐私政策HTML文件",
            "",
            "HTML Files (*.html *.htm);;All Files (*)"
        )
        if file_path:
            self.html_path = file_path
            self.html_path_label.setText(os.path.basename(file_path))
            self.html_path_label.setToolTip(file_path)
            self.check_can_analyze()

    def check_can_analyze(self):
        """检查是否可以开始分析（上传APK或HTML其中之一即可）"""
        if self.apk_path or self.html_path:
            self.analyze_btn.setEnabled(True)
        else:
            self.analyze_btn.setEnabled(False)

    def start_analysis(self):
        """开始分析"""
        if not self.apk_path and not self.html_path:
            QMessageBox.warning(self, "提示", "请至少上传APK文件或隐私政策文档！")
            return

        # 禁用按钮和显示进度条，启动线程等逻辑不变
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setVisible(True)
        self.status_label.setText("准备开始检测...")

        self.hide_empty_labels()

        self.analysis_thread = AnalysisThread(self.apk_path, self.html_path)
        self.analysis_thread.log_received.connect(self.update_log_console)


        self.analysis_thread.progress.connect(self.update_progress)
        self.analysis_thread.finished.connect(self.display_results)
        self.analysis_thread.error.connect(self.show_error)
        self.analysis_thread.start()

    def hide_empty_labels(self):
        """隐藏空提示标签"""
        self.policy_empty_label.setVisible(False)
        self.behavior_empty_label.setVisible(False)
        self.compliance_empty_label.setVisible(False)

    def update_progress(self, value, message):
        """更新进度"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def display_results(self, results):
        """显示检测结果"""
        # 隐藏进度条
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)

        # 启用按钮
        self.analyze_btn.setEnabled(True)

        # 显示隐私政策检测结果
        self.display_policy_results(results['policy'])

        # 显示应用行为分析结果
        self.display_behavior_results(results['behavior'])

        # 显示综合评估结果
        self.display_compliance_results(results['compliance'])

        # 显示完成消息
        QMessageBox.information(self, "完成", "隐私合规检测已完成！")

    def display_policy_results(self, policy_data):
        """显示左右排列的检测结果：左侧条款分类，右侧LLM解析"""
        self.policy_result_text.setVisible(True)

        included = policy_data.get('keywords_found', [])
        missing = policy_data.get('missing_clauses', [])
        score = policy_data.get('score', 0)
        llm_entities_list = policy_data.get('llm_entities', [])

        # 1. 顶部：评分区域 (全宽)
        html_content = f"""
        <div style="font-family: 'Microsoft YaHei', Arial; padding: 10px;">
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 10px; border: 1px solid #e0e0e0; margin-bottom: 20px;">
                <h2 style="margin: 0; color: #667eea;">隐私政策合规性深度分析报告 
                    <span style="float: right; color: {'#4CAF50' if score >= 80 else '#FF9800'};">评分: {score}</span>
                </h2>
            </div>

            <!-- 主容器：左右分栏 -->
            <div style="display: flex; flex-direction: row; width: 100%;">

                <!-- 左侧栏：条款分类结果 (占比约 35%) -->
                <div style="width: 35%; padding-right: 20px; border-right: 1px solid #eee;">
                    <h3 style="color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 5px;">已包含条款 ({len(included)})</h3>
                    <div style="background-color: #f1f8e9; padding: 10px; border-radius: 5px;">
                        <ul style="list-style-type: none; padding-left: 0; font-size: 12px; margin: 0;">
        """
        for item in included:
            html_content += f"<li style='margin-bottom: 4px; color: #2e7d32;'>● {item}</li>"

        html_content += f"""
                        </ul>
                    </div>

                    <h3 style="color: #F44336; border-bottom: 2px solid #F44336; padding-bottom: 5px; margin-top: 20px;"> 缺失条款 ({len(missing)})</h3>
                    <div style="background-color: #ffebee; padding: 10px; border-radius: 5px;">
                        <ul style="list-style-type: none; padding-left: 0; font-size: 12px; margin: 0;">
        """
        for item in missing:
            html_content += f"<li style='color: #d32f2f; margin-bottom: 4px;'>○ {item}</li>"

        html_content += """
                        </ul>
                    </div>
                </div>

                <!-- 右侧栏：LLM 关键行为解析 (占比约 65%) -->
                <div style="width: 65%; padding-left: 20px;">
                    <h3 style="color: #2196F3; border-bottom: 2px solid #2196F3; padding-bottom: 5px;"> LLM 深度提取结果 (数据处理行为)</h3>
        """

        if llm_entities_list:
            html_content += """
                    <table style="width: 100%; border-collapse: collapse; font-size: 12px; background-color: white;">
                        <thead>
                            <tr style="background-color: #e3f2fd; color: #1565c0;">
                                <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">动作</th>
                                <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">核心数据项</th>
                                <th style="border: 1px solid #dee2e6; padding: 8px; text-align: left;">目的/语境</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for item in llm_entities_list:
                entities = item.get('entities', [])
                if not entities: continue

                # 提取实体
                action = next((e['text'] for e in entities if e['label'] in ['collection', 'sharing', 'other']), "-")
                data_items = [e['text'] for e in entities if e['label'] == 'data']
                purpose = next((e['text'] for e in entities if e['label'] == 'purpose'), "-")

                html_content += f"""
                            <tr>
                                <td style="border: 1px solid #dee2e6; padding: 6px; font-weight: bold; color: #1e88e5;">{action}</td>
                                <td style="border: 1px solid #dee2e6; padding: 6px; color: #d32f2f;">{", ".join(data_items) if data_items else "-"}</td>
                                <td style="border: 1px solid #dee2e6; padding: 6px; color: #666;">{purpose}</td>
                            </tr>
                """
            html_content += "</tbody></table>"
        else:
            html_content += "<p style='color: #999; font-style: italic;'>未检测到具体的结构化数据处理行为。</p>"

        html_content += """
                </div>
            </div>

            <!-- 底部：风险警告 (全宽) -->
            <div style="margin-top: 25px; background-color: #fff3e0; padding: 15px; border-radius: 8px; border-left: 5px solid #ff9800;">
                <h4 style="margin: 0 0 10px 0; color: #e65100;">⚠️ 风险警告与合规建议</h4>
                <ul style="color: #bf360c; font-size: 12px; margin: 0; padding-left: 20px;">
        """
        if missing:
            html_content += f"<li><b>合规风险</b>：当前政策缺失 {len(missing)} 项核心条款，建议尽快补充。</li>"
        if any(e for item in llm_entities_list for e in item['entities'] if e['label'] == 'sharing'):
            html_content += "<li><b>共享风险</b>：检测到第三方共享行为，请核实是否已在文本中明示第三方名称及目的。</li>"

        html_content += """
                </ul>
            </div>
        </div>
        """
        self.policy_result_text.setHtml(html_content)

    def display_dynamic_results(self, dynamic_data):
        """显示动态分析的具体内容"""
        self.dynamic_empty_label.setVisible(False)
        self.dynamic_result_text.setVisible(True)

        # 获取数据
        apis = dynamic_data.get('sensitive_apis', [])
        network = dynamic_data.get('network_activities', [])
        coverage = dynamic_data.get('coverage_rate', 0)

        html_content = f"""
        <div style="font-family: 'Microsoft YaHei', Arial;">
            <h2 style="color: #667eea;">🚀 动态沙箱执行报告</h2>
            <hr>
            <div style="background-color: #e8f5e9; padding: 10px; border-radius: 5px;">
                <p><b>Activity 覆盖率:</b> <span style="font-size: 18px; color: #2e7d32;">{coverage*100:.2f}%</span></p>
            </div>

            <h3 style="color: #f44336; margin-top: 20px;">🚨 触发的敏感 API</h3>
            <div style="background-color: #fff5f5; border: 1px solid #feb2b2; padding: 10px;">
        """
        if apis:
            html_content += "<ul style='color: #c53030;'>"
            for api in apis:
                html_content += f"<li style='margin-bottom:5px;'>{api}</li>"
            html_content += "</ul>"
        else:
            html_content += "<p style='color: #666;'>未检测到敏感 API 调用</p>"

        html_content += """
            </div>

            <h3 style="color: #2b6cb0; margin-top: 20px;">🌐 网络传输活动</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <tr style="background-color: #ebf8ff;">
                    <th style="border: 1px solid #bee3f8; padding: 8px; text-align: left;">目标域名/请求</th>
                </tr>
        """
        if network:
            for item in network:
                html_content += f"<tr><td style='border: 1px solid #bee3f8; padding: 8px;'>{item}</td></tr>"
        else:
            html_content += "<tr><td style='padding: 8px; color: #999;'>未检测到外部网络连接</td></tr>"

        html_content += """
            </table>
        </div>
        """
        self.dynamic_result_text.setHtml(html_content)

    def display_behavior_results(self, behavior_data):
        """显示应用行为分析结果"""
        self.behavior_result_text.setVisible(True)

        risk_level = behavior_data.get('risk_level', 'unknown')
        risk_color = '#4CAF50' if risk_level == 'low' else '#FF9800' if risk_level == 'medium' else '#F44336'

        html_content = f"""
        <div style="font-family: 'Microsoft YaHei', Arial;">
            <h2 style="color: #667eea;">应用行为分析结果</h2>
            <hr>
            <h3>评分: <span style="color: {'#4CAF50' if behavior_data.get('score', 0) >= 80 else '#FF9800'};">{behavior_data.get('score', 0)}/100</span></h3>
            <p><b>包名:</b> {behavior_data.get('package_name', 'N/A')}</p>
            <p><b>风险等级:</b> <span style="color: {risk_color};">{risk_level}</span></p>
            <hr>

            <h3 style="color: #2196F3;">🔐 权限列表</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f0f0f0;">
                    <th style="padding: 8px; border: 1px solid #ddd;">权限名称</th>
                    <th style="padding: 8px; border: 1px solid #ddd;">危险等级</th>
                </tr>
        """

        for perm in behavior_data.get('permissions', []):
            color = '#F44336' if perm.get('level') == 'dangerous' else '#4CAF50'
            html_content += f"""
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">{perm.get('name', '')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: {color}; font-weight: bold;">{perm.get('level', '')}</td>
                </tr>
            """

        html_content += """
            </table>

            <h3 style="color: #FF9800;">⚡ 敏感API调用</h3>
            <ul>
        """

        for api in behavior_data.get('sensitive_apis', []):
            html_content += f"<li>{api}</li>"

        html_content += """
            </ul>
        </div>
        """

        self.behavior_result_text.setHtml(html_content)

    def display_compliance_results(self, compliance_data):
        """显示综合评估结果"""
        self.score_frame.setVisible(True)
        self.compliance_result_text.setVisible(True)

        score = compliance_data.get('overall_score', 0)
        self.score_label.setText(f"{score:.0f}")

        # 根据分数设置颜色
        if score >= 80:
            self.score_label.setStyleSheet("color: #4CAF50; font-size: 48px; font-weight: bold;")
            self.compliance_status_label.setText("✅ 合规")
            self.compliance_status_label.setStyleSheet("color: #4CAF50; font-size: 18px;")
        elif score >= 60:
            self.score_label.setStyleSheet("color: #FF9800; font-size: 48px; font-weight: bold;")
            self.compliance_status_label.setText("⚠️ 需要改进")
            self.compliance_status_label.setStyleSheet("color: #FF9800; font-size: 18px;")
        else:
            self.score_label.setStyleSheet("color: #F44336; font-size: 48px; font-weight: bold;")
            self.compliance_status_label.setText("❌ 不合规")
            self.compliance_status_label.setStyleSheet("color: #F44336; font-size: 18px;")

        html_content = f"""
        <div style="font-family: 'Microsoft YaHei', Arial;">
            <h2 style="color: #667eea;">📊 综合合规评估报告</h2>
            <hr>
            <h3>总体评分: {score:.1f}/100</h3>
            <p><b>合规状态:</b> {compliance_data.get('status', 'unknown')}</p>
            <p><b>生成时间:</b> {compliance_data.get('timestamp', 'N/A')}</p>
            <hr>

            <h3>📈 分项得分</h3>
            <ul>
                <li><b>隐私政策得分:</b> {compliance_data.get('policy_score', 0)}/100</li>
                <li><b>应用行为得分:</b> {compliance_data.get('behavior_score', 0)}/100</li>
            </ul>

            <h3 style="color: #F44336;">🚨 发现的问题</h3>
            <ul>
        """

        issues = compliance_data.get('issues', [])
        if issues:
            for issue in issues:
                html_content += f"<li style='color: red;'>{issue}</li>"
        else:
            html_content += "<li style='color: green;'>未发现严重问题</li>"

        html_content += """
            </ul>

            <h3 style="color: #2196F3;">💡 改进建议</h3>
            <ul>
        """

        suggestions = compliance_data.get('suggestions', [])
        if suggestions:
            for suggestion in suggestions:
                html_content += f"<li>{suggestion}</li>"
        else:
            html_content += "<li>当前应用隐私合规性良好</li>"

        html_content += """
            </ul>
        </div>
        """

        self.compliance_result_text.setHtml(html_content)

    def show_error(self, error_msg):
        """显示错误信息"""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.analyze_btn.setEnabled(True)

        QMessageBox.critical(self, "错误", error_msg)

    def reset_form(self):
        """重置表单"""
        # 重置文件路径
        self.apk_path = None
        self.html_path = None
        self.apk_path_label.setText('未选择文件')
        self.html_path_label.setText('未选择文件')
        self.apk_path_label.setToolTip('')
        self.html_path_label.setToolTip('')

        # 重置按钮状态
        self.analyze_btn.setEnabled(False)

        # 隐藏进度条
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        self.status_label.setVisible(False)
        self.status_label.setText('')

        # 显示空提示标签
        self.policy_empty_label.setVisible(True)
        self.behavior_empty_label.setVisible(True)
        self.compliance_empty_label.setVisible(True)

        # 隐藏并清空结果区域
        self.policy_result_text.setVisible(False)
        self.policy_result_text.clear()

        self.behavior_result_text.setVisible(False)
        self.behavior_result_text.clear()

        self.score_frame.setVisible(False)
        self.compliance_result_text.setVisible(False)
        self.compliance_result_text.clear()

        # 重置分数显示
        self.score_label.setText('--')
        self.score_label.setStyleSheet("color: #667eea; font-size: 48px; font-weight: bold;")
        self.compliance_status_label.setText('等待检测')
        self.compliance_status_label.setStyleSheet("color: gray; font-size: 18px;")

    def apply_styles(self):
        """应用样式表"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }

            #titleFrame {
                background-color: #667eea;
                border-radius: 10px;
                padding: 20px;
            }

            #mainTitle {
                color: white;
                font-size: 20px; /* 标题字体大小从 28px 减小到 20px */
                font-weight: bold;
            }

            #subtitle {
                color: white;
                font-size: 14px;
            }

            #uploadGroup {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                padding: 20px;
                font-size: 14px;
                font-weight: bold;
            }

            #fieldLabel {
                font-size: 13px;
                font-weight: normal;
                color: #333;
            }

            #pathLabel {
                background-color: #f9f9f9;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 8px;
                font-size: 12px;
                color: #555;
            }

            #apkButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: bold;
                min-width: 120px;
            }

            #apkButton:hover {
                background-color: #45a049;
            }

            #htmlButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: bold;
                min-width: 120px;
            }

            #htmlButton:hover {
                background-color: #0b7dda;
            }

            QProgressBar {
                border: 2px solid #667eea;
                border-radius: 5px;
                text-align: center;
                height: 30px;
                font-size: 13px;
            }

            QProgressBar::chunk {
                background-color: #667eea;
                border-radius: 3px;
            }

            #statusLabel {
                color: #667eea;
                font-size: 13px;
                font-weight: bold;
            }

            #analyzeButton {
                background-color: #667eea;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
            }

            #analyzeButton:hover {
                background-color: #5568d3;
            }

            #analyzeButton:disabled {
                background-color: #cccccc;
            }

            #resetButton {
                background-color: #f0f0f0;
                color: #333;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
            }

            #resetButton:hover {
                background-color: #e0e0e0;
            }

            #mainTabs {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
            }

            #mainTabs::pane {
                border: none;
                background-color: white;
            }

            QTabBar::tab {
                background-color: #f0f0f0;
                color: #666;
                padding: 12px 25px;
                margin-right: 5px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 14px;
                font-weight: bold;
            }

            QTabBar::tab:selected {
                background-color: #667eea;
                color: white;
            }

            QTabBar::tab:hover {
                background-color: #e0e0e0;
            }

            QTabBar::tab:selected:hover {
                background-color: #5568d3;
            }

            #pageTitle {
                font-size: 18px;
                font-weight: bold;
                color: #667eea;
                padding: 10px;
            }

            #emptyLabel {
                font-size: 16px;
                color: #999;
                padding: 100px;
            }

            #resultText {
                background-color: #fafafa;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 15px;
                font-size: 13px;
            }

            #scoreFrame {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                padding: 20px;
                margin: 10px 0;
            }

            #scoreLabel {
                font-size: 48px;
                font-weight: bold;
            }

            #complianceStatus {
                font-size: 18px;
                font-weight: bold;
            }
        """)


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    try:
        window = PrivacyComplianceUI()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"程序崩溃原因: {e}") # 这样你就能在控制台看到报错信息