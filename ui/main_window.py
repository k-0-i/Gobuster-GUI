from PySide6.QtWidgets import QMainWindow, QTabWidget, QVBoxLayout, QWidget
from ui.dir_tab import DirTab
from ui.dns_tab import DnsTab
from ui.fuzz_tab import FuzzTab
from ui.gcs_tab import GcsTab
from ui.s3_tab import S3Tab
from ui.tftp_tab import TftpTab
# from ui.version_tab import VersionTab
from ui.vhost_tab import VhostTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gobuster GUI")
        self.setGeometry(100, 100, 800, 600)

        # 创建主窗口布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # 创建 Tab Widget
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        # 加载各功能模块
        self.tabs.addTab(DirTab(), "目录爆破")
        self.tabs.addTab(DnsTab(), "DNS 爆破")
        self.tabs.addTab(FuzzTab(), "模糊测试")
        self.tabs.addTab(GcsTab(), "GCS 枚举")
        self.tabs.addTab(S3Tab(), "S3 枚举")
        self.tabs.addTab(TftpTab(), "TFTP 枚举")
        self.tabs.addTab(VhostTab(), "虚拟主机爆破")
        # self.tabs.addTab(VersionTab(), "版本信息")
