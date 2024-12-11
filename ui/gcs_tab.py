from PySide6.QtWidgets import (
    QWidget, QFormLayout, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QSpinBox, QTextEdit, QCheckBox, QFileDialog, QGroupBox, QLabel
)
from utils import CollapsibleBox
from PySide6.QtCore import Qt
from ui.result_window import ResultWindow

class GcsTab(QWidget):
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

        # 字典文件选择
        self.wordlist_input = QLineEdit()
        self.wordlist_button = QPushButton("选择字典")
        self.wordlist_button.clicked.connect(self.browse_wordlist)
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(self.wordlist_input)
        wordlist_layout.addWidget(self.wordlist_button)
        self.basic_layout.addRow("字典文件:", wordlist_layout)

        # 线程数
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 100)
        self.threads_input.setValue(10)
        self.basic_layout.addRow("线程数:", self.threads_input)

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

        # 高级设置
        self.advanced_box = CollapsibleBox("高级设置")
        self.advanced_layout = QFormLayout()

        self.add_advanced_options()
        self.advanced_box.setContentLayout(self.advanced_layout)
        self.layout.addWidget(self.advanced_box)

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

    def add_advanced_options(self):
        """添加高级选项"""
        self.maxfiles_input = QSpinBox()
        self.maxfiles_input.setRange(1, 100)
        self.maxfiles_input.setValue(5)
        self.advanced_layout.addRow("最大文件数 (--maxfiles):", self.maxfiles_input)

        self.proxy_input = QLineEdit()
        self.advanced_layout.addRow("代理 (--proxy):", self.proxy_input)

        self.random_agent_input = QCheckBox("随机用户代理 (--random-agent)")
        self.advanced_layout.addRow("", self.random_agent_input)

        self.no_tls_validation_input = QCheckBox("跳过 TLS 验证 (--no-tls-validation)")
        self.advanced_layout.addRow("", self.no_tls_validation_input)

        self.retry_input = QCheckBox("启用超时重试 (--retry)")
        self.advanced_layout.addRow("", self.retry_input)

        self.retry_attempts_input = QSpinBox()
        self.retry_attempts_input.setRange(1, 10)
        self.retry_attempts_input.setValue(3)
        self.advanced_layout.addRow("重试次数 (--retry-attempts):", self.retry_attempts_input)

        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("如: 10s")
        self.advanced_layout.addRow("HTTP 超时时间 (--timeout):", self.timeout_input)

        self.useragent_input = QLineEdit()
        self.advanced_layout.addRow("用户代理 (--useragent):", self.useragent_input)

        self.client_cert_p12_input = QLineEdit()
        self.client_cert_p12_button = QPushButton("选择 P12 文件")
        self.client_cert_p12_button.clicked.connect(self.browse_client_cert_p12)
        client_cert_p12_layout = QHBoxLayout()
        client_cert_p12_layout.addWidget(self.client_cert_p12_input)
        client_cert_p12_layout.addWidget(self.client_cert_p12_button)
        self.advanced_layout.addRow("客户端证书 (P12):", client_cert_p12_layout)

        self.client_cert_p12_password_input = QLineEdit()
        self.client_cert_p12_password_input.setEchoMode(QLineEdit.Password)
        self.advanced_layout.addRow("P12 文件密码 (--client-cert-p12-password):", self.client_cert_p12_password_input)

        self.client_cert_pem_input = QLineEdit()
        self.client_cert_pem_button = QPushButton("选择 PEM 文件")
        self.client_cert_pem_button.clicked.connect(self.browse_client_cert_pem)
        client_cert_pem_layout = QHBoxLayout()
        client_cert_pem_layout.addWidget(self.client_cert_pem_input)
        client_cert_pem_layout.addWidget(self.client_cert_pem_button)
        self.advanced_layout.addRow("客户端证书 (PEM):", client_cert_pem_layout)

        self.client_cert_pem_key_input = QLineEdit()
        self.client_cert_pem_key_button = QPushButton("选择 PEM 密钥")
        self.client_cert_pem_key_button.clicked.connect(self.browse_client_cert_pem_key)
        client_cert_pem_key_layout = QHBoxLayout()
        client_cert_pem_key_layout.addWidget(self.client_cert_pem_key_input)
        client_cert_pem_key_layout.addWidget(self.client_cert_pem_key_button)
        self.advanced_layout.addRow("客户端证书密钥 (--client-cert-pem-key):", client_cert_pem_key_layout)

    def bind_signals(self):
        """绑定信号以实时更新命令"""
        self.wordlist_input.textChanged.connect(self.update_command)
        self.threads_input.valueChanged.connect(self.update_command)
        self.maxfiles_input.valueChanged.connect(self.update_command)
        self.proxy_input.textChanged.connect(self.update_command)
        self.random_agent_input.stateChanged.connect(self.update_command)
        self.no_tls_validation_input.stateChanged.connect(self.update_command)
        self.retry_input.stateChanged.connect(self.update_command)
        self.retry_attempts_input.valueChanged.connect(self.update_command)
        self.timeout_input.textChanged.connect(self.update_command)
        self.useragent_input.textChanged.connect(self.update_command)
        self.debug_input.stateChanged.connect(self.update_command)
        self.delay_input.textChanged.connect(self.update_command)
        self.no_color_input.stateChanged.connect(self.update_command)
        self.no_error_input.stateChanged.connect(self.update_command)
        self.no_progress_input.stateChanged.connect(self.update_command)
        self.output_input.textChanged.connect(self.update_command)
        self.quiet_input.stateChanged.connect(self.update_command)
        self.client_cert_p12_input.textChanged.connect(self.update_command)
        self.client_cert_p12_password_input.textChanged.connect(self.update_command)
        self.client_cert_pem_input.textChanged.connect(self.update_command)
        self.client_cert_pem_key_input.textChanged.connect(self.update_command)

    def browse_wordlist(self):
        """选择字典文件"""
        wordlist_file, _ = QFileDialog.getOpenFileName(self, "选择字典文件")
        if wordlist_file:
            self.wordlist_input.setText(wordlist_file)

    def browse_output_file(self):
        """选择输出文件"""
        output_file, _ = QFileDialog.getSaveFileName(self, "选择输出文件", filter="All Files (*)")
        if output_file:
            self.output_input.setText(output_file)

    def browse_client_cert_p12(self):
        """选择 P12 客户端证书文件"""
        cert_file, _ = QFileDialog.getOpenFileName(self, "选择 P12 客户端证书文件", filter="P12 Files (*.p12)")
        if cert_file:
            self.client_cert_p12_input.setText(cert_file)

    def browse_client_cert_pem(self):
        """选择 PEM 客户端证书文件"""
        cert_file, _ = QFileDialog.getOpenFileName(self, "选择 PEM 客户端证书文件", filter="PEM Files (*.pem)")
        if cert_file:
            self.client_cert_pem_input.setText(cert_file)

    def browse_client_cert_pem_key(self):
        """选择 PEM 客户端证书密钥文件"""
        key_file, _ = QFileDialog.getOpenFileName(self, "选择 PEM 客户端证书密钥文件", filter="Key Files (*.key)")
        if key_file:
            self.client_cert_pem_key_input.setText(key_file)

    def update_command(self):
        """根据用户输入生成 Gobuster 命令"""
        import os
        import sys

        # 获取脚本的上一级当前路径
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 构建 gobuster 的可执行文件路径
        directory_path = os.path.join(base_dir, 'bin')  # ./bin 目录

        # 构建完整的 gobuster 命令
        if "linux" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster'), "gcs"]
        elif "win" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster.exe'), "gcs"]

        if self.wordlist_input.text():
            command.extend(["-w", self.wordlist_input.text()])
        command.extend(["-t", str(self.threads_input.value())])

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

        if self.advanced_box.toggle_button.isChecked():
            command.extend(["--maxfiles", str(self.maxfiles_input.value())])

            if self.proxy_input.text():
                command.extend(["--proxy", self.proxy_input.text()])

            if self.random_agent_input.isChecked():
                command.append("--random-agent")

            if self.no_tls_validation_input.isChecked():
                command.append("--no-tls-validation")

            if self.retry_input.isChecked():
                command.append("--retry")
                command.extend(["--retry-attempts", str(self.retry_attempts_input.value())])

            if self.timeout_input.text():
                command.extend(["--timeout", self.timeout_input.text()])

            if self.useragent_input.text():
                command.extend(["-a", self.useragent_input.text()])

            if self.client_cert_p12_input.text():
                command.extend(["--client-cert-p12", self.client_cert_p12_input.text()])

            if self.client_cert_p12_password_input.text():
                command.extend(["--client-cert-p12-password", self.client_cert_p12_password_input.text()])

            if self.client_cert_pem_input.text():
                command.extend(["--client-cert-pem", self.client_cert_pem_input.text()])

            if self.client_cert_pem_key_input.text():
                command.extend(["--client-cert-pem-key", self.client_cert_pem_key_input.text()])
        # 强制不显示进度
        command.append("--no-progress")
        self.command_output.setText(" ".join(command))

    def start_scan(self):
        """开始扫描"""
        command = self.command_output.toPlainText().split(" ")
        self.result_window = ResultWindow(command)
        self.result_window.exec()
