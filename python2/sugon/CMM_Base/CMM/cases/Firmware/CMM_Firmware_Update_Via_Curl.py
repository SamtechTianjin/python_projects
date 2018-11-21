# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time,datetime
import json
import re
from Collect_Firmware import collectFirmware
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
CSRFToken = ""
DOWNLOAD_FW_FAIL = False
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

def result_operation(flag, temp_text):
    if flag.upper() == "PASS":
        show_step_result(temp_text, "PASS")
        CMM.save_step_result(main_log, temp_text, flag="PASS")
    else:
        show_step_result(temp_text, "FAIL")
        CMM.save_step_result(main_log, temp_text, flag="FAIL")

def prepareFlashArea():
    restapi = '/api/maintenance/flash'
    cmd = "curl -X PUT -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    print("status: {0}".format(status))
    print("output: {0}".format(output))

def uploadFirmware(filename):
    pass

def verifyFirmware():
    pass

def flashFirmware():
    pass

def getFlashStatus():
    pass




class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def b_download_fw(self):
        global CASE_PASS
        global DOWNLOAD_FW_FAIL
        message = "- Download CMM Firmware -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        status = collectFirmware("/home/CMMBuild/KLS/Release", "CMM")
        if not status:
            CASE_PASS = False
            DOWNLOAD_FW_FAIL = True
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            result_operation("FAIL",temp_text)
        else:
            result_operation("PASS",temp_text)

    def c_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        if DOWNLOAD_FW_FAIL:
            LOGIN_FAIL = True
            return False
        CMM.show_message(format_item("Login Web"),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            message = "[curl] Login Web successfully."
            CMM.save_data(main_log, message,timestamp=False)
            show_step_result("[curl] Login Web", flag="PASS")
            CSRFToken = output.strip()
        else:
            CASE_PASS = False
            message = "[curl] Login Web FAIL !"
            MAIN_LOG_list.append(message)
            message = "{0}\n{1}".format(message,output)
            CMM.save_data(main_log, message,timestamp=False)
            show_step_result("[curl] Login Web", flag="FAIL")
            LOGIN_FAIL = True

    def d_prepare_flash_area(self):
        if LOGIN_FAIL:
            return False
        message = "- Prepare Flash Area -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        prepareFlashArea()

    def e_upload_fw(self):
        if LOGIN_FAIL:
            return False
        message = "- Upload Firmware -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")

    def f_verify_fw(self):
        if LOGIN_FAIL:
            return False
        message = "- Verify Firmware -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")

    def g_flash_firmware(self):
        if LOGIN_FAIL:
            return False
        message = "- Flash Firmware -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")




    def y_curl_logout(self):
        if LOGIN_FAIL:
            return False
        CMM.show_message(format_item("Logout Web"),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
        if status == 0:
            message = "[curl] Logout Web successfully."
            CMM.save_data(main_log, message,timestamp=False)
            show_step_result("[curl] Logout Web", flag="PASS")
        else:
            message = "[curl] Logout Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message,timestamp=False)
            show_step_result("[curl] Logout Web", flag="FAIL")

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