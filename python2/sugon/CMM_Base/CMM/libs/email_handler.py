# -*- coding:utf-8 -*-

import os,sys
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from common import CMM
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf import common_config


"""
获取CMM最新迭代版本CMM_version
"""
def collectCMMVersion():
    vers = 0
    for item in os.listdir(common_config.IMAGE_DIR):
        if item.startswith("CMM"):
            m = re.search(r'\d+',item)
            if m:
                try:
                    temp_vers = int(m.group())
                except: pass
                else:
                    if temp_vers >= vers:
                        vers = temp_vers
    return vers


class MailSender(object):

    HOST = "smtp.163.com"
    FROM = "samtech_sugon@163.com"
    PASSWD = "samtech912"
    SUBJECT_default = u"CMM自动化测试报告".encode("utf-8")
    SUBJECT = common_config.EMAIL_SUBJECT or SUBJECT_default
    TO = common_config.EMAIL_ADDRS

    def __init__(self):
        self.create_content()
        message = MIMEMultipart()
        message["From"] = self.FROM
        message["To"] = ",".join(self.TO)  # 此处多个邮箱为一个字符串，以逗号分隔
        message["Subject"] = self.SUBJECT
        # message.attach(MIMEText(self.CONTENT, "plain", "utf-8"))
        message.attach(MIMEText(self.CONTENT, "html", "utf-8"))    # HTML格式邮件
        # 添加邮件附件
        for item in os.listdir(common_config.LOG_DIR):
            if item.endswith(".pdf"):
                filename = os.path.join(common_config.LOG_DIR, item)
                attachment = MIMEText(open(filename, "rb").read(), "base64", "utf-8")
                attachment["Content-Type"] = 'application/octet-stream'
                attachment["Content-Disposition"] = 'attachment;filename="{0}"'.format(item)
                message.attach(attachment)
        self.message = message

    def create_content(self):
        total_num,pass_num,fail_num,date = "","","",""
        with open(common_config.MAIN_LOG,"r") as f:
            line = f.readline().strip()
            while line:
                for index,item in enumerate(["total case:","pass case:","fail case:","Test start"]):
                    m = re.search(r'{0}.*'.format(item),line)
                    if m:
                        if index == 3:
                            date = line.split()[0]
                        else:
                            num = m.group().split(":")[-1].strip()
                            if index == 0:
                                total_num = num
                            elif index == 1:
                                pass_num = num
                            elif index == 2:
                                fail_num = num
                        break
                line = f.readline().strip()
        vers = collectCMMVersion()
        CMM_version = "CMMSprint{0}".format(vers) if vers else "Unknown"
        self.CONTENT = common_config.EMAIL_CONTENT.format(date,total_num,pass_num,fail_num,CMM_version)

    def send(self):
        log_info = "[mail]"
        try:
            server = smtplib.SMTP(host=self.HOST, port=25)
            server.login(self.FROM, self.PASSWD)
            server.sendmail(self.FROM, common_config.EMAIL_ADDRS, self.message.as_string())  # 此处多个邮箱为一个列表
            server.quit()
            log_info = " ".join([log_info, "Send successfully."])
        except Exception as e:
            log_info = " ".join([log_info, "Send FAIL !\n{0}".format(e)])
        finally:
            CMM.save_data(common_config.MAIN_LOG, log_info)

    @classmethod
    def finish_email(cls):
        e_mail = cls()
        e_mail.send()


if __name__ == '__main__':
    MailSender.finish_email()