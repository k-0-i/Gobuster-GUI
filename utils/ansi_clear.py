# utils.py

import re

def ansi_to_html(text):
    """将 ANSI 转义序列转换为 HTML，不替换空格"""
    # 定义 ANSI 转义序列的正则表达式
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    # ANSI 转 HTML 样式映射
    styles = {
        '0': '</span>',  # 重置
        '1': '<span style="font-weight: bold;">',  # 加粗
        '30': '<span style="color: black;">',  # 黑色
        '31': '<span style="color: red;">',  # 红色
        '32': '<span style="color: green;">',  # 绿色
        '33': '<span style="color: yellow;">',  # 黄色
        '34': '<span style="color: blue;">',  # 蓝色
        '35': '<span style="color: magenta;">',  # 品红
        '36': '<span style="color: cyan;">',  # 青色
        '37': '<span style="color: white;">',  # 白色
        '90': '<span style="color: gray;">',  # 灰色
    }

    # 替换 ANSI 转义序列为 HTML
    def replace_match(match):
        codes = match.group(0)[2:-1].split(';')
        html_styles = [styles.get(code, '') for code in codes]
        return ''.join(html_styles)

    text = ansi_escape.sub(replace_match, text)  # 替换 ANSI 转义序列

    # 特定格式处理
    text = re.sub(r'\(Status: 200\)', r'<span style="color: green;">(Status: 200)</span>', text)
    text = re.sub(r'\(Status: 404\)', r'<span style="color: red;">(Status: 404)</span>', text)
    text = re.sub(r'\(Status: 302\)', r'<span style="color: blue;">(Status: 302)</span>', text)
    text = re.sub(r'\(Status: 301\)', r'<span style="color: blue;">(Status: 301)</span>', text)
    text = re.sub(r'\[Status=200\]', r'<span style="color: green;">[Status=200]</span>', text)
    # 替换换行符为 HTML 换行
    # text = text.replace('\n', '<br>')  # 替换换行符为 HTML 换行

    # 替换重置序列
    text = text.replace('\x1B[0m', '</span>')  # 替换重置序列

    return text
