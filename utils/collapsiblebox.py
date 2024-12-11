# utils.py
from PySide6.QtWidgets import QFrame, QPushButton, QVBoxLayout, QWidget, QSizePolicy, QScrollArea


class CollapsibleBox(QFrame):
    def __init__(self, title=""):
        super().__init__()
        self.toggle_button = QPushButton()
        self.toggle_button.setStyleSheet("text-align: left;")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.setText(title)
        self.toggle_button.clicked.connect(self.toggle)

        self.content_area = QWidget()
        self.content_area.setMaximumHeight(0)
        self.content_area.setMinimumHeight(0)

        # 设置合适的SizePolicy
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.content_area.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.addWidget(self.toggle_button)
        self.main_layout.addWidget(self.content_area)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 使用 QScrollArea 来包裹内容
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        self.inner_widget = QWidget()
        self.inner_layout = QVBoxLayout(self.inner_widget)
        self.inner_layout.setContentsMargins(0, 0, 0, 0)
        self.inner_layout.setSpacing(0)

        self.scroll_area.setWidget(self.inner_widget)

        content_layout = QVBoxLayout(self.content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        content_layout.addWidget(self.scroll_area)

    def toggle(self):
        if self.toggle_button.isChecked():
            self.content_area.setMaximumHeight(16777215)
            self.content_area.setMinimumHeight(0)
        else:
            self.content_area.setMaximumHeight(0)
            self.content_area.setMinimumHeight(0)

        self.content_area.adjustSize()
        self.adjustSize()
        self.updateGeometry()

        # 检测父窗口状态，如果全屏或最大化则不递归调用adjustSize()
        parent = self.parentWidget()
        while parent:
            # 尝试获取顶级窗口
            top_window = parent.window()
            if top_window and (top_window.isFullScreen() or top_window.isMaximized()):
                # 在全屏或最大化状态下不进行adjustSize，避免Wayland协议错误
                break
            parent.adjustSize()
            parent = parent.parentWidget()

    def setContentLayout(self, layout):
        self.inner_layout.addLayout(layout)
