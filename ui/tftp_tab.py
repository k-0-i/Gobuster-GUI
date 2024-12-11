from PySide6.QtWidgets import (
    QWidget, QFormLayout, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QSpinBox, QTextEdit, QCheckBox, QFileDialog, QGroupBox, QLabel
)
from utils import CollapsibleBox
from PySide6.QtCore import Qt
from ui.result_window import ResultWindow

class TftpTab(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(1000, 700)
        self.setMinimumWidth(800)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(10)

        # 基本设置
        self.basic_group = QGroupBox("基本设置")
        self.basic_layout = QFormLayout(self.basic_group)

        # TFTP服务器
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("如: tftp://example.com")
        self.basic_layout.addRow("TFTP 服务器 (--server):", self.server_input)

        # 超时时间
        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("如: 1s")
        self.basic_layout.addRow("超时时间 (--timeout):", self.timeout_input)

        self.layout.addWidget(self.basic_group)

        # 全局设置
        self.global_box = CollapsibleBox("全局设置")
        self.global_layout = QFormLayout()

        self.debug_input = QCheckBox("启用调试输出 (--debug)")
        self.global_layout.addRow("", self.debug_input)

        self.delay_input = QLineEdit()
        self.delay_input.setPlaceholderText("如: 1500ms")
        self.global_layout.addRow("请求间隔 (--delay):", self.delay_input)

        self.no_color_input = QCheckBox("禁用颜色输出 (--no-color)")
        self.global_layout.addRow("", self.no_color_input)

        self.no_error_input = QCheckBox("不显示错误 (--no-error)")
        self.global_layout.addRow("", self.no_error_input)

        self.no_progress_input = QCheckBox("不显示进度 (--no-progress)")
        self.global_layout.addRow("", self.no_progress_input)

        self.output_input = QLineEdit()
        self.output_button = QPushButton("选择输出文件")
        self.output_button.clicked.connect(self.browse_output_file)
        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(self.output_button)
        self.global_layout.addRow("输出文件 (--output):", output_layout)

        self.quiet_input = QCheckBox("静默模式 (--quiet)")
        self.global_layout.addRow("", self.quiet_input)

        self.verbose_input = QCheckBox("详细输出 (--verbose)")
        self.global_layout.addRow("", self.verbose_input)

        self.global_box.setContentLayout(self.global_layout)
        self.layout.addWidget(self.global_box)

        # 命令输出框
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.layout.addWidget(QLabel("生成命令:"))
        self.layout.addWidget(self.command_output)

        # 开始按钮
        self.start_button = QPushButton("开始扫描")
        self.start_button.clicked.connect(self.start_scan)
        self.layout.addWidget(self.start_button)

        # 实时更新命令
        self.update_command()

        # 绑定信号以实时更新命令
        self.bind_signals()

    def bind_signals(self):
        """绑定信号以实时更新命令"""
        self.server_input.textChanged.connect(self.update_command)
        self.timeout_input.textChanged.connect(self.update_command)
        self.debug_input.stateChanged.connect(self.update_command)
        self.delay_input.textChanged.connect(self.update_command)
        self.no_color_input.stateChanged.connect(self.update_command)
        self.no_error_input.stateChanged.connect(self.update_command)
        self.no_progress_input.stateChanged.connect(self.update_command)
        self.output_input.textChanged.connect(self.update_command)
        self.quiet_input.stateChanged.connect(self.update_command)

    def browse_output_file(self):
        """选择输出文件"""
        output_file, _ = QFileDialog.getSaveFileName(self, "选择输出文件", filter="All Files (*)")
        if output_file:
            self.output_input.setText(output_file)

    def update_command(self):
        """根据用户输入生成 Gobuster 命令"""
        import os
        import sys

        # 获取脚本的上一级路径
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 构建 gobuster 的可执行文件路径
        directory_path = os.path.join(base_dir, 'bin')  # ./bin 目录

        # 构建完整的 gobuster 命令
        if "linux" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster'), "tftp"]
        elif "win" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster.exe'), "tftp"]

        if self.server_input.text():
            command.extend(["-s", self.server_input.text()])

        if self.timeout_input.text():
            command.extend(["--timeout", self.timeout_input.text()])

        if self.global_box.toggle_button.isChecked():
            if self.debug_input.isChecked():
                command.append("--debug")

            if self.delay_input.text():
                command.extend(["--delay", self.delay_input.text()])

            if self.no_color_input.isChecked():
                command.append("--no-color")

            if self.no_error_input.isChecked():
                command.append("--no-error")

            if self.no_progress_input.isChecked():
                command.append("--no-progress")

            if self.output_input.text():
                command.extend(["--output", self.output_input.text()])

            if self.quiet_input.isChecked():
                command.append("--quiet")
        # 强制不显示进度
        command.append("--no-progress")
        self.command_output.setText(" ".join(command))

    def start_scan(self):
        """开始扫描"""
        command = self.command_output.toPlainText().split(" ")
        self.result_window = ResultWindow(command)
        self.result_window.exec()
