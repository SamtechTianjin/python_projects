# -*- coding:utf-8 -*-

import os
import datetime

# 控制是否执行测试
RUN = True
# 定义目录及文件
MAIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
LOG_DIR = os.path.join(MAIN_DIR, "logs")
LIB_DIR = os.path.join(MAIN_DIR, "libs")
CONF_DIR = os.path.join(MAIN_DIR, "conf")
CASE_DIR = os.path.join(MAIN_DIR, "cases")
TMP_DIR = os.path.join(MAIN_DIR, "tmp")
MAIN_LOG = os.path.join(LOG_DIR, "main.log")
PDF_RESULT = os.path.join(LOG_DIR, "CMM_Report_{0}.pdf".format(datetime.datetime.now().strftime("%Y-%m-%d")))
CASE_CONFIG = os.path.join(CONF_DIR, "cases.txt")
# 定义console显示的一些参数
TITLE_LENGTH = 64
LINE_SPACING = 1

# 邮件参数设定
SEND_MAIL = False
EMAIL_SUBJECT = "CMM Test Report"
EMAIL_ADDRS = [
    "samtech_sugon@163.com",
    "samliuming@aliyun.com",
    "liuming1@sugon.com",
]
# HTML格式邮件
EMAIL_CONTENT = """
<h2 style="margin-left: 100px;margin-top: 20px">CMM自动化测试</h2>
<div style="margin-left: 40px;margin-top: 5px;font-size: 16px;font-weight: bold">
    <p>测试日期：{0}<span style="margin-left: 40px">测试版本：{4}</span></p>
    <p style="color: blue">测试总数：{1}</p>
    <p style="color: green">测试通过：{2}</p>
    <p style="color: red">测试失败：{3}</p>
    <p>具体测试结果请参考附件测试报告。</p>
</div><br/><br/>
<div style="color: gray;font-size: 12px;margin-left: 40px">
    <div>刘明 17622916681</div>
    <div>服务器产品事业部</div>
    <div>曙光信息产业股份有限公司</div>
    <div>天津市西青区华苑产业园区海泰华科大街15号</div>
</div>
"""