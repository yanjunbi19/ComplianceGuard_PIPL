"""
隐私合规检测系统 - 主程序入口
"""
import sys
from PyQt5.QtWidgets import QApplication
from ui_controller import PrivacyComplianceUI
# main.py
import os
import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication

from ui_controller import PrivacyComplianceUI

def main():
    # ===== High DPI（必须在 QApplication 创建前）=====
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    # 如需固定缩放可启用（示例）：os.environ["QT_SCALE_FACTOR"] = "1.25"

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)

    # ===== 全局字体（和你当前 UI 样式匹配）=====
    app.setFont(QFont("Microsoft YaHei", 10))

    window = PrivacyComplianceUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序崩溃原因: {e}")
        import traceback
        traceback.print_exc()