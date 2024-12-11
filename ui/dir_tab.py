from PySide6.QtWidgets import (
    QWidget, QFormLayout, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QSpinBox, QTextEdit, QCheckBox, QComboBox, QFileDialog, QGroupBox, QLabel, QSizePolicy
)
from PySide6.QtCore import Qt
from ui.result_window import ResultWindow
from utils import CollapsibleBox


class DirTab(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(1000, 700)
        # 设置一个最小宽度，避免折叠/展开后窗口变得过窄
        self.setMinimumWidth(800)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(10)

        # 基本设置
        self.basic_group = QGroupBox("基本设置")
        self.basic_layout = QFormLayout(self.basic_group)

        # URL 输入
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("如: http://example.com")
        self.basic_layout.addRow("目标 URL:", self.url_input)

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

        # 全局选项（全部命令模块）
        self.global_box = CollapsibleBox("全局选项")
        global_layout = QFormLayout()

        # 全局标志
        self.debug_input = QCheckBox("启用调试(--debug)")
        global_layout.addRow("", self.debug_input)

        self.delay_input = QLineEdit()
        self.delay_input.setPlaceholderText("如 1500ms")
        global_layout.addRow("请求间隔 (--delay):", self.delay_input)

        self.no_error_input = QCheckBox("不显示错误(--no-error)")
        global_layout.addRow("", self.no_error_input)

        self.no_color_input = QCheckBox("禁用颜色(--no-color)")
        global_layout.addRow("", self.no_color_input)

        self.no_progress_input = QCheckBox("不显示进度(--no-progress)")
        global_layout.addRow("", self.no_progress_input)

        self.output_input = QLineEdit()
        self.output_button = QPushButton("选择输出文件")
        self.output_button.clicked.connect(self.browse_output_file)
        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(self.output_button)
        global_layout.addRow("输出文件 (--output):", output_layout)

        # global_layout.addRow("输出文件(--output):", self.output_input)

        self.pattern_input = QLineEdit()
        global_layout.addRow("替换模式文件(--pattern):", self.pattern_input)

        self.quiet_input = QCheckBox("静默模式(--quiet)")
        global_layout.addRow("", self.quiet_input)

        self.verbose_input = QCheckBox("详细输出(--verbose)")
        global_layout.addRow("", self.verbose_input)

        self.wordlist_offset_input = QSpinBox()
        self.wordlist_offset_input.setRange(0, 9999999)
        global_layout.addRow("字典偏移量(--wordlist-offset):", self.wordlist_offset_input)

        self.global_box.setContentLayout(global_layout)
        self.layout.addWidget(self.global_box)

        # 高级设置（常用）使用 CollapsibleBox
        self.advanced_box = CollapsibleBox("高级设置（常用）")
        adv_layout = QVBoxLayout()

        # HTTP 设置
        self.http_group = QGroupBox("HTTP 设置")
        self.http_group.setCheckable(True)
        self.http_group.setChecked(True)
        http_inner = QWidget()
        self.http_group_layout = QFormLayout(http_inner)

        self.method_input = QComboBox()
        self.method_input.addItems(["GET", "POST", "HEAD", "PUT", "DELETE"])
        self.http_group_layout.addRow("HTTP 方法:", self.method_input)

        self.useragent_input = QLineEdit()
        self.http_group_layout.addRow("用户代理:", self.useragent_input)

        self.follow_redirect_input = QCheckBox("跟随重定向")
        self.http_group_layout.addRow("", self.follow_redirect_input)

        self.random_agent_input = QCheckBox("随机用户代理")
        self.http_group_layout.addRow("", self.random_agent_input)

        self.no_tls_validation_input = QCheckBox("跳过 TLS 验证")
        self.http_group_layout.addRow("", self.no_tls_validation_input)

        self.http_group.setLayout(QVBoxLayout())
        self.http_group.layout().addWidget(http_inner)
        self.http_group.toggled.connect(lambda checked: http_inner.setVisible(checked))
        http_inner.setVisible(self.http_group.isChecked())
        adv_layout.addWidget(self.http_group)

        # 状态码过滤
        self.status_group = QGroupBox("状态码过滤")
        self.status_group.setCheckable(True)
        self.status_group.setChecked(True)
        status_inner = QWidget()
        self.status_group_layout = QFormLayout(status_inner)
        self.status_codes_input = QLineEdit()
        self.status_group_layout.addRow("状态码 (包含):", self.status_codes_input)
        self.status_codes_blacklist_input = QLineEdit()
        self.status_group_layout.addRow("状态码 (排除):", self.status_codes_blacklist_input)

        self.status_group.setLayout(QVBoxLayout())
        self.status_group.layout().addWidget(status_inner)
        self.status_group.toggled.connect(lambda checked: status_inner.setVisible(checked))
        status_inner.setVisible(self.status_group.isChecked())
        adv_layout.addWidget(self.status_group)

        # 代理设置
        self.proxy_group = QGroupBox("代理设置")
        self.proxy_group.setCheckable(True)
        self.proxy_group.setChecked(False)
        proxy_inner = QWidget()
        self.proxy_group_layout = QFormLayout(proxy_inner)
        self.proxy_input = QLineEdit()
        self.proxy_group_layout.addRow("代理:", self.proxy_input)

        self.proxy_group.setLayout(QVBoxLayout())
        self.proxy_group.layout().addWidget(proxy_inner)
        self.proxy_group.toggled.connect(lambda checked: proxy_inner.setVisible(checked))
        proxy_inner.setVisible(self.proxy_group.isChecked())
        adv_layout.addWidget(self.proxy_group)

        self.advanced_box.setContentLayout(adv_layout)
        self.layout.addWidget(self.advanced_box)

        # 额外设置（不常用）
        self.extra_box = CollapsibleBox("额外设置（不常用）")
        extra_layout = QVBoxLayout()

        # 其他选项
        self.other_group = QGroupBox("其他选项")
        self.other_group.setCheckable(True)
        self.other_group.setChecked(False)
        other_inner = QWidget()
        self.other_group_layout = QFormLayout(other_inner)
        self.add_slash_input = QCheckBox("在每个请求后添加 /")
        self.other_group_layout.addRow("", self.add_slash_input)

        self.discover_backup_input = QCheckBox("搜索备份文件")
        self.other_group_layout.addRow("", self.discover_backup_input)

        self.expanded_mode_input = QCheckBox("扩展模式（显示完整URL）")
        self.other_group_layout.addRow("", self.expanded_mode_input)

        self.cookies_input = QLineEdit()
        self.other_group_layout.addRow("Cookies:", self.cookies_input)

        self.headers_input = QLineEdit()
        self.other_group_layout.addRow("HTTP 头信息(逗号分隔):", self.headers_input)

        self.other_group.setLayout(QVBoxLayout())
        self.other_group.layout().addWidget(other_inner)
        self.other_group.toggled.connect(lambda checked: other_inner.setVisible(checked))
        other_inner.setVisible(self.other_group.isChecked())
        extra_layout.addWidget(self.other_group)

        # TLS 选项
        self.tls_group = QGroupBox("TLS 选项")
        self.tls_group.setCheckable(True)
        self.tls_group.setChecked(False)
        tls_inner = QWidget()
        self.tls_group_layout = QFormLayout(tls_inner)
        self.client_cert_p12_input = QLineEdit()
        self.client_cert_p12_button = QPushButton("选择 P12 文件")
        self.client_cert_p12_button.clicked.connect(self.browse_client_cert_p12)
        client_cert_p12_layout = QHBoxLayout()
        client_cert_p12_layout.addWidget(self.client_cert_p12_input)
        client_cert_p12_layout.addWidget(self.client_cert_p12_button)
        self.tls_group_layout.addRow("TLS 客户端证书 (P12):", client_cert_p12_layout)

        self.client_cert_p12_password_input = QLineEdit()
        self.client_cert_p12_password_input.setEchoMode(QLineEdit.Password)
        self.tls_group_layout.addRow("P12 文件密码:", self.client_cert_p12_password_input)

        self.client_cert_pem_input = QLineEdit()
        self.client_cert_pem_button = QPushButton("选择 PEM 文件")
        self.client_cert_pem_button.clicked.connect(self.browse_client_cert_pem)
        client_cert_pem_layout = QHBoxLayout()
        client_cert_pem_layout.addWidget(self.client_cert_pem_input)
        client_cert_pem_layout.addWidget(self.client_cert_pem_button)
        self.tls_group_layout.addRow("TLS 客户端证书 (PEM):", client_cert_pem_layout)

        self.client_cert_pem_key_input = QLineEdit()
        self.client_cert_pem_key_button = QPushButton("选择 PEM 密钥文件")
        self.client_cert_pem_key_button.clicked.connect(self.browse_client_cert_pem_key)
        client_cert_pem_key_layout = QHBoxLayout()
        client_cert_pem_key_layout.addWidget(self.client_cert_pem_key_input)
        client_cert_pem_key_layout.addWidget(self.client_cert_pem_key_button)
        self.tls_group_layout.addRow("TLS 客户端证书密钥:", client_cert_pem_key_layout)

        self.tls_group.setLayout(QVBoxLayout())
        self.tls_group.layout().addWidget(tls_inner)
        self.tls_group.toggled.connect(lambda checked: tls_inner.setVisible(checked))
        tls_inner.setVisible(self.tls_group.isChecked())
        extra_layout.addWidget(self.tls_group)

        # 文件与扩展名
        self.file_group = QGroupBox("文件与扩展名")
        self.file_group.setCheckable(True)
        self.file_group.setChecked(False)
        file_inner = QWidget()
        self.file_group_layout = QFormLayout(file_inner)
        self.extensions_input = QLineEdit()
        self.file_group_layout.addRow("文件扩展名:", self.extensions_input)
        self.extensions_input.setPlaceholderText("如： .php,.js,.html(多个后缀使用,隔开)")

        self.extensions_file_input = QLineEdit()
        self.extensions_file_button = QPushButton("选择扩展名文件")
        self.extensions_file_button.clicked.connect(self.browse_extensions_file)
        extensions_file_layout = QHBoxLayout()
        extensions_file_layout.addWidget(self.extensions_file_input)
        extensions_file_layout.addWidget(self.extensions_file_button)
        self.file_group_layout.addRow("扩展名文件:", extensions_file_layout)

        self.file_group.setLayout(QVBoxLayout())
        self.file_group.layout().addWidget(file_inner)
        self.file_group.toggled.connect(lambda checked: file_inner.setVisible(checked))
        file_inner.setVisible(self.file_group.isChecked())
        extra_layout.addWidget(self.file_group)

        # 输出与重试
        self.output_retry_group = QGroupBox("输出与重试")
        self.output_retry_group.setCheckable(True)
        self.output_retry_group.setChecked(False)
        output_retry_inner = QWidget()
        self.output_retry_layout = QFormLayout(output_retry_inner)
        self.exclude_length_input = QLineEdit()
        self.output_retry_layout.addRow("排除内容长度:", self.exclude_length_input)

        self.hide_length_input = QCheckBox("隐藏内容长度")
        self.output_retry_layout.addRow("", self.hide_length_input)

        self.no_status_input = QCheckBox("不显示状态码")
        self.output_retry_layout.addRow("", self.no_status_input)

        self.retry_input = QCheckBox("启用重试")
        self.output_retry_layout.addRow("", self.retry_input)

        self.retry_attempts_input = QSpinBox()
        self.retry_attempts_input.setRange(1, 10)
        self.retry_attempts_input.setValue(3)
        self.output_retry_layout.addRow("重试次数:", self.retry_attempts_input)

        self.timeout_input = QLineEdit()
        self.output_retry_layout.addRow("HTTP 超时时间:", self.timeout_input)

        self.output_retry_group.setLayout(QVBoxLayout())
        self.output_retry_group.layout().addWidget(output_retry_inner)
        self.output_retry_group.toggled.connect(lambda checked: output_retry_inner.setVisible(checked))
        output_retry_inner.setVisible(self.output_retry_group.isChecked())
        extra_layout.addWidget(self.output_retry_group)

        # 身份认证
        self.auth_group = QGroupBox("身份认证")
        self.auth_group.setCheckable(True)
        self.auth_group.setChecked(False)
        auth_inner = QWidget()
        self.auth_layout = QFormLayout(auth_inner)
        self.username_input = QLineEdit()
        self.auth_layout.addRow("基本认证用户名:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.auth_layout.addRow("基本认证密码:", self.password_input)

        self.auth_group.setLayout(QVBoxLayout())
        self.auth_group.layout().addWidget(auth_inner)
        self.auth_group.toggled.connect(lambda checked: auth_inner.setVisible(checked))
        auth_inner.setVisible(self.auth_group.isChecked())
        extra_layout.addWidget(self.auth_group)

        self.extra_box.setContentLayout(extra_layout)
        self.layout.addWidget(self.extra_box)

        # 命令输出框
        self.layout.addWidget(QLabel("生成命令:"))
        self.command_output = QTextEdit()
        self.command_output.setReadOnly(True)
        self.command_output.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.layout.addWidget(self.command_output)

        # 开始按钮
        self.start_button = QPushButton("开始扫描")
        self.layout.addWidget(self.start_button, alignment=Qt.AlignRight)

        # 利用伸缩因子控制相对大小
        # 基本设置较小，高级与额外设置以及全局设置相对较大
        # self.layout.setStretchFactor(self.basic_group, 1)
        # self.layout.setStretchFactor(self.advanced_box, 2)
        # self.layout.setStretchFactor(self.extra_box, 2)
        # self.layout.setStretchFactor(self.global_box, 1)
        # self.layout.setStretchFactor(self.command_output, 1)
        # self.layout.setStretchFactor(self.start_button, 0)

        # 实时更新命令
        self.update_command()

        # 绑定信号
        self.bind_signals()

    def bind_signals(self):
        self.url_input.textChanged.connect(self.update_command)
        self.wordlist_input.textChanged.connect(self.update_command)
        self.threads_input.valueChanged.connect(self.update_command)
        self.method_input.currentTextChanged.connect(self.update_command)
        self.status_codes_input.textChanged.connect(self.update_command)
        self.status_codes_blacklist_input.textChanged.connect(self.update_command)
        self.useragent_input.textChanged.connect(self.update_command)
        self.follow_redirect_input.stateChanged.connect(self.update_command)
        self.random_agent_input.stateChanged.connect(self.update_command)
        self.no_tls_validation_input.stateChanged.connect(self.update_command)
        self.proxy_input.textChanged.connect(self.update_command)

        self.add_slash_input.stateChanged.connect(self.update_command)
        self.client_cert_p12_input.textChanged.connect(self.update_command)
        self.client_cert_p12_password_input.textChanged.connect(self.update_command)
        self.client_cert_pem_input.textChanged.connect(self.update_command)
        self.client_cert_pem_key_input.textChanged.connect(self.update_command)
        self.cookies_input.textChanged.connect(self.update_command)
        self.discover_backup_input.stateChanged.connect(self.update_command)
        self.exclude_length_input.textChanged.connect(self.update_command)
        self.expanded_mode_input.stateChanged.connect(self.update_command)
        self.extensions_input.textChanged.connect(self.update_command)
        self.extensions_file_input.textChanged.connect(self.update_command)
        self.headers_input.textChanged.connect(self.update_command)
        self.hide_length_input.stateChanged.connect(self.update_command)
        self.no_status_input.stateChanged.connect(self.update_command)
        self.username_input.textChanged.connect(self.update_command)
        self.password_input.textChanged.connect(self.update_command)
        self.retry_input.stateChanged.connect(self.update_command)
        self.retry_attempts_input.valueChanged.connect(self.update_command)
        self.timeout_input.textChanged.connect(self.update_command)

        # CollapsibleBox的展开/折叠操作
        self.advanced_box.toggle_button.clicked.connect(self.update_command)
        self.extra_box.toggle_button.clicked.connect(self.update_command)
        self.global_box.toggle_button.clicked.connect(self.update_command)

        self.debug_input.stateChanged.connect(self.update_command)
        self.delay_input.textChanged.connect(self.update_command)
        self.no_error_input.stateChanged.connect(self.update_command)
        self.no_color_input.stateChanged.connect(self.update_command)
        self.no_progress_input.stateChanged.connect(self.update_command)
        self.output_input.textChanged.connect(self.update_command)
        self.pattern_input.textChanged.connect(self.update_command)
        self.quiet_input.stateChanged.connect(self.update_command)
        self.verbose_input.stateChanged.connect(self.update_command)
        self.wordlist_offset_input.valueChanged.connect(self.update_command)

        self.start_button.clicked.connect(self.start_scan)

    def browse_wordlist(self):
        wordlist_file, _ = QFileDialog.getOpenFileName(self, "选择字典文件")
        if wordlist_file:
            self.wordlist_input.setText(wordlist_file)

    def browse_client_cert_p12(self):
        cert_p12_file, _ = QFileDialog.getOpenFileName(self, "选择 P12 证书文件", filter="P12 Files (*.p12)")
        if cert_p12_file:
            self.client_cert_p12_input.setText(cert_p12_file)

    def browse_client_cert_pem(self):
        cert_pem_file, _ = QFileDialog.getOpenFileName(self, "选择 PEM 证书文件", filter="PEM Files (*.pem)")
        if cert_pem_file:
            self.client_cert_pem_input.setText(cert_pem_file)

    def browse_client_cert_pem_key(self):
        cert_pem_key_file, _ = QFileDialog.getOpenFileName(self, "选择 PEM 密钥文件", filter="Key Files (*.key)")
        if cert_pem_key_file:
            self.client_cert_pem_key_input.setText(cert_pem_key_file)

    def browse_extensions_file(self):
        extensions_file, _ = QFileDialog.getOpenFileName(self, "选择扩展名文件",
                                                         filter="Text Files (*.txt);;All Files (*)")
        if extensions_file:
            self.extensions_file_input.setText(extensions_file)

    def browse_output_file(self):
        """选择输出文件"""
        output_file, _ = QFileDialog.getSaveFileName(self, "选择输出文件", filter="All Files (*)")
        if output_file:
            self.output_input.setText(output_file)

    def update_command(self):

        import os
        import sys

        # 获取脚本的当前路径
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 构建 gobuster 的可执行文件路径
        directory_path = os.path.join(base_dir, 'bin')  # ./bin 目录

        # 构建完整的 gobuster 命令
        if "linux" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster'), "dir"]
        elif "win" in sys.platform:
            command = [os.path.join(directory_path, 'gobuster.exe'), "dir"]


        # 基本设置
        if self.url_input.text():
            command.extend(["-u", self.url_input.text()])
        if self.wordlist_input.text():
            command.extend(["-w", self.wordlist_input.text()])
        command.extend(["-t", str(self.threads_input.value())])

        # 高级设置
        if self.advanced_box.toggle_button.isChecked():
            if self.method_input.currentText() != "GET":
                command.extend(["-m", self.method_input.currentText()])
            if self.status_codes_input.text():
                command.extend(["-s", self.status_codes_input.text()])
            if self.status_codes_blacklist_input.text():
                command.extend(["-b", self.status_codes_blacklist_input.text()])
            if self.useragent_input.text():
                command.extend(["-a", self.useragent_input.text()])
            if self.follow_redirect_input.isChecked():
                command.append("-r")
            if self.random_agent_input.isChecked():
                command.append("--random-agent")
            if self.no_tls_validation_input.isChecked():
                command.append("-k")
            if self.proxy_input.text():
                command.extend(["--proxy", self.proxy_input.text()])

        # 额外设置
        if self.extra_box.toggle_button.isChecked():
            if self.other_group.isChecked():
                if self.add_slash_input.isChecked():
                    command.append("-f")
                if self.discover_backup_input.isChecked():
                    command.append("-d")
                if self.expanded_mode_input.isChecked():
                    command.append("-e")
                if self.cookies_input.text():
                    command.extend(["-c", self.cookies_input.text()])
                if self.headers_input.text():
                    headers = self.headers_input.text().split(',')
                    for header in headers:
                        h = header.strip()
                        if h:
                            command.extend(["-H", h])
            if self.tls_group.isChecked():
                if self.client_cert_p12_input.text():
                    command.extend(["--client-cert-p12", self.client_cert_p12_input.text()])
                if self.client_cert_p12_password_input.text():
                    command.extend(["--client-cert-p12-password", self.client_cert_p12_password_input.text()])
                if self.client_cert_pem_input.text():
                    command.extend(["--client-cert-pem", self.client_cert_pem_input.text()])
                if self.client_cert_pem_key_input.text():
                    command.extend(["--client-cert-pem-key", self.client_cert_pem_key_input.text()])
            if self.file_group.isChecked():
                if self.extensions_input.text():
                    command.extend(["-x", self.extensions_input.text()])
                if self.extensions_file_input.text():
                    command.extend(["-X", self.extensions_file_input.text()])
            if self.output_retry_group.isChecked():
                if self.exclude_length_input.text():
                    command.extend(["--exclude-length", self.exclude_length_input.text()])
                if self.hide_length_input.isChecked():
                    command.append("--hide-length")
                if self.no_status_input.isChecked():
                    command.append("-n")
                if self.retry_input.isChecked():
                    command.append("--retry")
                    command.extend(["--retry-attempts", str(self.retry_attempts_input.value())])
                if self.timeout_input.text():
                    command.extend(["--timeout", self.timeout_input.text()])
            if self.auth_group.isChecked():
                if self.username_input.text():
                    command.extend(["-U", self.username_input.text()])
                if self.password_input.text():
                    command.extend(["-P", self.password_input.text()])

        # 全局选项
        if self.global_box.toggle_button.isChecked():
            if self.debug_input.isChecked():
                command.append("--debug")
            if self.delay_input.text():
                command.extend(["--delay", self.delay_input.text()])
            if self.no_error_input.isChecked():
                command.append("--no-error")
            if self.no_color_input.isChecked():
                command.append("--no-color")
            if self.no_progress_input.isChecked():
                command.append("--no-progress")
            if self.output_input.text():
                command.extend(["--output", self.output_input.text()])
            if self.pattern_input.text():
                command.extend(["--pattern", self.pattern_input.text()])
            if self.quiet_input.isChecked():
                command.append("--quiet")
            if self.verbose_input.isChecked():
                command.append("--verbose")
            if self.wordlist_offset_input.value() > 0:
                command.extend(["--wordlist-offset", str(self.wordlist_offset_input.value())])

        # 强制不显示进度
        command.append("--no-progress")

        self.command_output.setText(" ".join(command))

    def start_scan(self):
        command = self.command_output.toPlainText().split(" ")
        print(command)
        self.result_window = ResultWindow(command)
        self.result_window.exec()
