# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time
import shutil
import json
import re
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG,TMP_DIR
from libs.common import CMM,unicode_convert
from libs.console_show import format_item,show_step_result
import conf.config as config

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR,module_name)
main_log = os.path.join(log_dir,"{0}.log".format(module_name))
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD

# Global variable
LOGIN_FAIL = False
DUMP_FAIL = False
CSRFToken = ""
BLACK_BOX_FILE_PATH = os.path.join(TMP_DIR,"blackBox.tar")
BLACK_BOX_FOLDER_PATH = os.path.join(TMP_DIR,"blackBoxInfo")
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)


def dumpCMMBlackBoxInfo():
    dumpAPI = "/api/maintenance/dump_bmc_blackinfo"
    saveAPI = "/bsod/bmcblackinfo.tar"
    # Dump Black box info
    cmd = "curl -X PUT -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie" %(CSRFToken,IP,dumpAPI)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Dump Black box info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        texts = ["[Dump Exception]","{0}".format(output)]
        for text in texts:
            MAIN_LOG_list.append(text)
            CMM.show_message(text,timestamp=False,color="red")
        return False
    # Save Black box info
    if os.path.exists(BLACK_BOX_FILE_PATH):
        os.remove(BLACK_BOX_FILE_PATH)
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie > %s" %(CSRFToken,IP,saveAPI,BLACK_BOX_FILE_PATH)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Save Black box info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        texts = ["[Save Exception]","{0}".format(output)]
        for text in texts:
            MAIN_LOG_list.append(text)
            CMM.show_message(text,timestamp=False,color="red")
        return False
    return True

def checkCMMBlackBoxInfo():
    """
    Audit log: 对比API返回的日志数目和黑盒文件中的日志数目(AuditLog.txt)
    SEL: 对比IPMI命令返回值和黑盒文件中的日志数目(SEL_RAW.txt和SEL_TRANSLATE.txt)
    """
    if os.path.exists(BLACK_BOX_FOLDER_PATH):
        shutil.rmtree(BLACK_BOX_FOLDER_PATH)
    os.mkdir(BLACK_BOX_FOLDER_PATH)
    cmd = "tar -xvf {0} -C {1}".format(BLACK_BOX_FILE_PATH,BLACK_BOX_FOLDER_PATH)
    status,output = CMM.run_cmd(cmd)
    message = "Uncompress tar file\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        auditLogPath = os.path.join(BLACK_BOX_FOLDER_PATH,"var/bmcblackinfo/Log/AuditLog.txt")
        selRawPath = os.path.join(BLACK_BOX_FOLDER_PATH,"var/bmcblackinfo/Log/SEL_RAW.txt")
        selTranslatePath = os.path.join(BLACK_BOX_FOLDER_PATH,"var/bmcblackinfo/Log/SEL_TRANSLATE.txt")
        auditNumViaAPI = parseAuditAPI()
        auditNumViaBlackBox = parseAuditBlackBox(auditLogPath)
        selNumViaIPMI = parseSelIPMI()
        selNumViaRaw = parseSelRaw(selRawPath)
        selNumViaTranslate = parseSelTranslate(selTranslatePath)
        names = [
            "Audit log number via API",
            "Audit log number via Black box(AuditLog.txt)",
            "SEL number via IPMI",
            "SEL number via Black box(SEL_RAW.txt)",
            "SEL number via Black box(SEL_TRANSLATE.txt)"
        ]
        nums = [auditNumViaAPI,auditNumViaBlackBox,selNumViaIPMI,selNumViaRaw,selNumViaTranslate]
        for index in range(len(names)):
            tempString = ": ".join([names[index],str(nums[index])])
            CMM.save_data(main_log,tempString,timestamp=False)
            CMM.show_message(tempString,timestamp=False,color="blue")
        if auditNumViaAPI == auditNumViaBlackBox != "Unknown" and selNumViaIPMI == selNumViaRaw == selNumViaTranslate != "Unknown":
            pass
        else:
            text = "The number of log does not match !"
            MAIN_LOG_list.append(text)
            CMM.show_message(text,timestamp=False,color="red")
            return False
    else:
        texts = ["[Uncompress Exception]","{0}".format(output)]
        for text in texts:
            MAIN_LOG_list.append(text)
            CMM.show_message(text,timestamp=False,color="red")
        return False
    return True

def parseAuditAPI():
    auditLogNum = "Unknown"
    auditAPI = "/api/logs/auditlog"
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type: application/json\" -d \"{'audit_pagesize':20,'audit_pages':1,'log_starttime':-1,'log_endtime':-1,'log_selected':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,auditAPI)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Collect Audit log info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Collect audit log] {0}".format(e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
            MAIN_LOG_list.append(message)
        else:
            if isinstance(json_data,dict) and json_data.get("error"):
                CMM.show_message("{0}".format(output),timestamp=False,color="red")
                MAIN_LOG_list.append("{0}".format(output))
            elif isinstance(json_data,list) and json_data:
                auditLogNum = json_data[0].get("total_count")
    return auditLogNum

def parseAuditBlackBox(filename):
    num = "Unknown"
    with open(filename, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            elif line.startswith("ID"):
                continue
            elif re.match(r'\d+',line):
                num = re.match(r'\d+',line).group()
                num = int(num)
                break
    return num

def parseSelRaw(filename):
    num = "Unknown"
    with open(filename, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            temp = line.split("|")[0].strip()
            if re.search(r'ID',temp) or not temp or re.search(r'-',temp):
                continue
            else:
                num = int(temp.strip("h"),16)
                break
    return num

def parseSelTranslate(filename):
    num = "Unknown"
    with open(filename, "r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            temp = line.split("|")[0].strip()
            if re.search(r'ID',temp):
                continue
            else:
                num = int(temp)
                break
    return num

def parseSelIPMI():
    num = "Unknown"
    cmd = "{0} sel elist".format(IPMITOOL)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[IPMI] Collect SEL info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        tempList = output.splitlines()
        if not tempList[-1]:
            num = tempList[-2].split("|")[0].strip()
            num = int(num,16)
        else:
            num = tempList[-1].split("|")[0].strip()
            num = int(num,16)
    return num




class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def b_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        message = "Login Web"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log,message,"PASS")
            CSRFToken = output.strip()
        else:
            LOGIN_FAIL = True
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
            MAIN_LOG_list.append("{0} FAIL !".format(message))

    def c_collect_blackbox_info(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        global DUMP_FAIL
        message = "- Collect Black box info -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append(message)
        temp_text = message.strip(" -")
        is_FAIL = False
        status = dumpCMMBlackBoxInfo()
        if not status:
            is_FAIL = True
        if is_FAIL:
            DUMP_FAIL = True
            CASE_PASS = False
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")

    def d_check_blackbox_info(self):
        if LOGIN_FAIL:
            return False
        if DUMP_FAIL:
            return False
        global CASE_PASS
        message = "- Check Black box info -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append(message)
        temp_text = message.strip(" -")
        is_FAIL = False
        status = checkCMMBlackBoxInfo()
        if not status:
            is_FAIL = True
        if is_FAIL:
            CASE_PASS = False
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")

    def y_curl_logout(self):
        if LOGIN_FAIL:
            return False
        message = "Logout Web"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
        if status == 0:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")
        else:
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")

    def z_finish(self):
        CMM.save_data(MAIN_LOG,"{0} {1}".format("PASS:" if CASE_PASS else "FAIL:",module_name.replace("_"," ")))
        infos = map(lambda x: "INFO: {0}".format(x),MAIN_LOG_list)
        for info in infos:
            CMM.save_data(MAIN_LOG, info, timestamp=False)
        time.sleep(5)

if __name__ == '__main__':
    func_list = list()
    funcs = dir(CMMTest)
    for func in funcs:
        if re.match(r'[a-z]{1}_\w+$', func):
            func_list.append(func)
    suite = unittest.TestSuite()
    suite.addTests(map(CMMTest, func_list))
    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(suite)