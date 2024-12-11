import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

def load_stylesheet():
    """加载 QSS 样式表"""
    with open("assets/style.qss", "r") as file:
        return file.read()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # app.setStyleSheet(load_stylesheet())  # 加载样式表
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


