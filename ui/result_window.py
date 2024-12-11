from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTextEdit, QPushButton, QFileDialog, QHBoxLayout
)
from PySide6.QtCore import QProcess
from PySide6.QtGui import QTextCursor
from utils import ansi_to_html

class ResultWindow(QDialog):
    def __init__(self, command):
        super().__init__()
        self.setWindowTitle("执行结果")
        self.setGeometry(300, 200, 800, 400)

        # 布局
        self.layout = QVBoxLayout(self)

        # 富文本框显示结果
        self.result_output = QTextEdit(self)
        self.result_output.setReadOnly(True)
        self.result_output.setStyleSheet("font-family: Consolas; font-size: 10pt;")  # 使用等宽字体
        self.layout.addWidget(self.result_output)

        # 按钮布局
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        # 保存按钮
        self.save_button = QPushButton("保存结果", self)
        self.save_button.setFixedWidth(80)  # 设置按钮固定宽度，让按钮不会太大
        self.save_button.clicked.connect(self.save_results)
        button_layout.addWidget(self.save_button)

        # 停止按钮
        self.stop_button = QPushButton("停止", self)
        self.stop_button.setFixedWidth(60)  # 设置按钮固定宽度
        self.stop_button.clicked.connect(self.stop_process)
        button_layout.addWidget(self.stop_button)

        # 关闭按钮
        self.close_button = QPushButton("关闭", self)
        self.close_button.setFixedWidth(60)  # 设置按钮固定宽度
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)

        # 将按钮布局加入主布局
        self.layout.addLayout(button_layout)

        # 命令执行
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)

        # 执行命令
        command_str = ' '.join(command)
        html_command = ansi_to_html(command_str)
        self.result_output.insertHtml(
            f"<div style='white-space: pre-wrap;'><b>正在执行命令:</b><br>{html_command}<br></div>"
        )
        self.process.start(command[0], command[1:])

    def handle_stdout(self):
        """处理标准输出"""
        data = self.process.readAllStandardOutput().data().decode("utf-8", errors="ignore")
        html_data = ansi_to_html(data)
        self.result_output.insertHtml(f"<div style='white-space: pre-wrap;'>{html_data}</div>")
        self.result_output.moveCursor(QTextCursor.End)

    def handle_stderr(self):
        """处理标准错误"""
        data = self.process.readAllStandardError().data().decode("utf-8", errors="ignore")
        html_data = ansi_to_html(data)
        self.result_output.insertHtml(f"<div style='white-space: pre-wrap; color: red;'>{html_data}</div>")
        self.result_output.moveCursor(QTextCursor.End)

    def process_finished(self):
        """处理命令执行完成"""
        self.result_output.insertHtml("<div style='white-space: pre-wrap;'><br><b>命令执行完成。</b></div>")
        self.close_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def save_results(self):
        """保存运行结果到文件"""
        file_dialog = QFileDialog(self)
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_dialog.setNameFilter("Text Files (*.txt);;All Files (*)")
        file_dialog.setDefaultSuffix("txt")
        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            with open(file_path, 'w', encoding='utf-8') as file:
                plain_text = self.result_output.toPlainText()
                file.write(plain_text)

    def stop_process(self):
        """停止命令执行"""
        if self.process.state() == QProcess.Running:
            self.process.kill()
            self.result_output.insertHtml("<div style='white-space: pre-wrap; color: red;'><br><b>命令已被用户终止。</b></div>")
            self.close_button.setEnabled(True)
            self.stop_button.setEnabled(False)
