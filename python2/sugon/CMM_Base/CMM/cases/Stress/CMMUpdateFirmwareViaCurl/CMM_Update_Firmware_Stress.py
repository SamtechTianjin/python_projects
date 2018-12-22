# -*- coding:utf-8 -*-

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
from libs.common import CMM,unicode_convert,Remote
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
STRESS_TIME = config.FIRMWARE_UPDATE_TIME

# Global variable

IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
IMAGE_FILE = ""
CMM_RESTORE_TIME = 300
CSRFToken = ""
DOWNLOAD_FW_FAIL = True
LOGIN_FAIL = True
ENTER_FLASH_MODE = False
UPLOAD_IMAGE = False
VERIFY_IMAGE = False

def result_operation(flag, temp_text):
    if flag.upper() == "PASS":
        CMM.save_step_result(main_log, temp_text, flag="PASS")
    else:
        CMM.save_step_result(main_log, temp_text, flag="FAIL")

def enterFlashMode():
    restapi = '/api/maintenance/flash'
    cmd = "curl -X PUT -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "Enter Flash Mode\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    message = "Enter flash mode"
    if status != 0:
        MAIN_LOG_list.append("{0} FAIL !".format(message))
        return False
    return True

def uploadFirmware():
    is_fail = False
    restapi = "/api/maintenance/firmware"
    if not IMAGE_FILE:
        temp_text = "Image name error !"
        MAIN_LOG_list.append(temp_text)
        CMM.show_message(temp_text,timestamp=False,color="red")
        CMM.save_data(main_log,temp_text,timestamp=False)
        return False
    cmd = "curl -F \"fwimage=@%s\" -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(IMAGE_FILE,CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "Upload Firmware\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    message = "Upload firmware"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_fail = True
            temp_text = "[Exception] {0}".format(e)
            CMM.show_message(temp_text,timestamp=False,color="red")
            CMM.save_data(temp_text,temp_text,timestamp=False)
        else:
            if json_data.get("cc") != 0:
                is_fail = True
                MAIN_LOG_list.append("{0}".format(output))
    else:
        is_fail = True
    if is_fail:
        MAIN_LOG_list.append("{0} FAIL !".format(message))
    return False if is_fail else True

def verifyFirmware():
    restapi = "/api/maintenance/firmware/verification"
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "Verify Firmware\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    message = "Verify Firmware"
    if status != 0 or not output:
        MAIN_LOG_list.append("{0} FAIL !".format(message))
        return False
    return True

def flashFirmware():
    is_fail = False
    restapi = "/api/maintenance/firmware/upgrade"
    cmd = "curl -X PUT -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'preserve_config':0,'flash_status':1}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "Flash Firmware\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    message = "Flash Firmware"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            CMM.show_message(temp_text,timestamp=False,color="red")
            CMM.save_data(main_log,temp_text,timestamp=False)
        else:
            if json_data.get("error"):
                is_fail = True
                MAIN_LOG_list.append("{0}".format(output))
    else:
        is_fail = True
    if is_fail:
        MAIN_LOG_list.append("{0} FAIL !".format(message))
    return False if is_fail else True

def getFlashStatus():
    restapi = "/api/maintenance/firmware/flash-progress"
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    wait_time = 300
    start_time = datetime.datetime.now()
    while CMM.calc_time_interval(start_time,datetime.datetime.now()) < wait_time:
        status, output = CMM.retry_run_cmd(cmd)
        message = "Get Flash Status\n{0}\nreturncode: {1}\n{2}".format(cmd, status, output)
        CMM.save_data(main_log, message, timestamp=False)
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            CMM.show_message(temp_text,timestamp=False,color="red")
            CMM.save_data(main_log,temp_text,timestamp=False)
        else:
            if re.search(r'Completed',json_data.get("progress"),re.IGNORECASE):
                break
        time.sleep(0.5)
    else:
        return False
    return True

def checkFwVersion():
    vers = "Unknown"
    cmd = "{0} raw 0x06 0x01".format(IPMITOOL)
    status,output = CMM.retry_run_cmd(cmd)
    temp_text = "Check CMM firmware version\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,temp_text,timestamp=False)
    if status == 0:
        temp_vers = ""
        temp_list = output.split()
        try:
            """ eg: 00 21 >>> 0.21 """
            for item in temp_list[2:4]:
                temp = int(item,10)
                if temp_vers:
                    temp_vers += ".{0}".format(temp)
                else:
                    temp_vers += "{0}".format(temp)
            vers = temp_vers
        except Exception as e:
            message = "[Exception Check FW Version] {0}".format(e)
            CMM.show_message(message,timestamp=False,color="red")
            CMM.save_data(main_log,message,timestamp=False)
    return vers




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
        global IMAGE_FILE
        message = "- Download CMM Firmware -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        flag = "CMM"
        status = collectFirmware(flag)
        if not status:
            CASE_PASS = False
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            CMM.save_step_result(main_log,temp_text,"FAIL")
            show_step_result(temp_text,"FAIL")
        else:
            DOWNLOAD_FW_FAIL = False
            IMAGE_FILE = os.path.join(TMP_DIR,"{0}.ima".format(flag))
            CMM.save_data(main_log,"Image file: {0}".format(IMAGE_FILE),timestamp=False)
            CMM.save_step_result(main_log, temp_text, "PASS")
            show_step_result(temp_text,"PASS")

    def d_flash_fw_stress(self):
        global LOGIN_FAIL, CSRFToken, ENTER_FLASH_MODE, UPLOAD_IMAGE, VERIFY_IMAGE
        global CASE_PASS
        if DOWNLOAD_FW_FAIL:
            return False
        loop_num = 0
        start_time = datetime.datetime.now()
        baseline_vers = ""
        while CMM.calc_time_interval(start_time,datetime.datetime.now()) < STRESS_TIME:
            LOGIN_FAIL = False
            CSRFToken = ""
            ENTER_FLASH_MODE = False
            UPLOAD_IMAGE = False
            VERIFY_IMAGE = False
            loop_num += 1
            vers = checkFwVersion()
            temp_text = "\n[Loop{0}] Currert FW version: {1}\n".format(loop_num,vers)
            CMM.show_message(temp_text, timestamp=False, color="blue")
            CMM.save_data(main_log,temp_text,timestamp=False)
            if loop_num == 1 and vers != "Unknown":
                baseline_vers = vers
            else:
                if baseline_vers:
                    if baseline_vers != vers:
                        CASE_PASS = False
                        temp_text = "Expect CMM version: {0}".format(baseline_vers)
                        MAIN_LOG_list.append(temp_text)
                        CMM.save_data(main_log,temp_text,timestamp=False)
                        CMM.show_message(temp_text,timestamp=False,color="red")
                        temp_text = "Current CMM version: {0}".format(vers)
                        MAIN_LOG_list.append(temp_text)
                        CMM.save_data(main_log,temp_text,timestamp=False)
                        CMM.show_message(temp_text,timestamp=False,color="red")
                        return False
                else:
                    CASE_PASS = False
                    temp_text = "Check FW version: {0}".format(vers)
                    MAIN_LOG_list.append(temp_text)
                    CMM.save_data(main_log,temp_text,timestamp=False)
                    CMM.show_message(temp_text, timestamp=False, color="red")
                    return False
            # Login web
            message = "Login Web"
            CMM.show_message(format_item(message), color="green", timestamp=False)
            status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD, retry_count=1)
            if status == 0:
                CSRFToken = output.strip()
                show_step_result(message, "PASS")
                CMM.save_step_result(main_log, message, "PASS")
            else:
                LOGIN_FAIL = True
                CASE_PASS = False
                show_step_result(message, "FAIL")
                CMM.save_step_result(main_log, message, "FAIL")
            # Enter flash mode
            if LOGIN_FAIL:
                return False
            message = "Enter flash mode"
            CMM.show_message(format_item(message), color="green", timestamp=False)
            status = enterFlashMode()
            if status:
                ENTER_FLASH_MODE = True
                show_step_result(message, flag="PASS")
                CMM.save_step_result(main_log, message, flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message, flag="FAIL")
                CMM.save_step_result(main_log, message, flag="FAIL")
            # Upload firmware image
            if not ENTER_FLASH_MODE:
                return False
            message = "Upload firmware"
            CMM.show_message(format_item(message), color="green", timestamp=False)
            status = uploadFirmware()
            if status:
                UPLOAD_IMAGE = True
                show_step_result(message, flag="PASS")
                CMM.save_step_result(main_log, message, flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message, flag="FAIL")
                CMM.save_step_result(main_log, message, flag="FAIL")
            # Verify firmware image
            if not UPLOAD_IMAGE:
                return False
            message = "Verify firmware"
            CMM.show_message(format_item(message), color="green", timestamp=False)
            status = verifyFirmware()
            if status:
                VERIFY_IMAGE = True
                show_step_result(message, flag="PASS")
                CMM.save_step_result(main_log, message, flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message, flag="FAIL")
                CMM.save_step_result(main_log, message, flag="FAIL")
            # Flash firmware
            if not VERIFY_IMAGE:
                return False
            message = "Flash firmware"
            CMM.show_message(format_item(message), color="green", timestamp=False)
            status = flashFirmware()
            if status:
                complete_status = getFlashStatus()
                if complete_status:
                    show_step_result(message, flag="PASS")
                    CMM.save_step_result(main_log, message, flag="PASS")
                else:
                    CASE_PASS = False
                    show_step_result(message, flag="FAIL")
                    CMM.save_step_result(main_log, message, flag="FAIL")
            else:
                CASE_PASS = False
                show_step_result(message, flag="FAIL")
                CMM.save_step_result(main_log, message, flag="FAIL")
            # 刷新步骤结束 检测是否刷新完成继续下一次刷新
            if not CASE_PASS:
                temp_text = "[Loop{0}] Flash CMM firmware FAIL, exit...".format(loop_num)
                CMM.save_data(MAIN_LOG, temp_text)
                CMM.show_message(temp_text, timestamp=False, color="red")
                break
            else:
                """
                刷新固件后 如果不能正常登录网页(retry_count=3) 则停止测试
                刷新后 第一次登录会失败
                """
                time.sleep(CMM_RESTORE_TIME)
                status, output = CMM.curl_login_logout(IP,flag="login",username=USERNAME,password=PASSWORD,retry_count=3)
                if status == 0 and output:
                    csrftoken = output.strip()
                    time.sleep(1)
                    status, output = CMM.curl_login_logout(IP,flag="logout",username=USERNAME,password=PASSWORD,csrf_token=csrftoken)
                    if status != 0:
                        temp_text = "Logout Web FAIL after update firmware, exit..."
                        CMM.save_data(MAIN_LOG, temp_text, timestamp=False)
                        CMM.show_message(temp_text, timestamp=False, color="red")
                        break
                else:
                    temp_text = "Login Web FAIL after update firmware, exit..."
                    CMM.save_data(MAIN_LOG, temp_text, timestamp=False)
                    CMM.show_message(temp_text, timestamp=False, color="red")
                    break
        else:
            temp_text = "- Stress Time: {0}s, loop number: {1}".format(STRESS_TIME,loop_num)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="blue")


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