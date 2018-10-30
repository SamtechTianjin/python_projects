# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import json
import re
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG
from libs.common import CMM,unicode_convert
from libs.console_show import format_item
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
FAN_NUM = config.FAN_NUM

# Global variable
LOG_FAIL = False
CSRFToken = ""
GET_FAN_API = "/api/cmminfo/fans/"
GET_FAN_OEM = "raw 0x3a 0x53"
SET_FAN_OEM = "raw 0x3a 0x52"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
MANUAL_MODE_CMD = "{0} raw 0x3a 0x5a 0x04 0x03 0x00".format(IPMITOOL)
AUTO_MODE_CMD = "{0} raw 0x3a 0x5a 0x04 0x03 0x01".format(IPMITOOL)

"""
API接口返回值:
id,FanPresent,Present,FanStatus,FanSpeed1,FanSpeed2,Duty
"""

# 获得指定id的风扇信息--OEM  id从1开始
def GetFanInfoViaOEM(id):
    cmd_id = id - 1
    fan_info = None
    cmd = "{0} {1} 0x0{2} 2>/dev/null".format(IPMITOOL,GET_FAN_OEM,cmd_id)
    status,output = CMM.run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("FAN {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[OEM] Get FAN{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        fan_info = output
    return "" if not fan_info else fan_info

# 获得指定id的风扇信息--API  id从1开始
def GetFanInfoViaAPI(CSRFToken,id):
    fan_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d\"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_FAN_API)
    status,output = CMM.run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("FAN {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get FAN{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            fan_info = json.loads(output.strip())
            if isinstance(fan_info,list):
                fan_info = fan_info[0]
        except Exception as e:
            temp = "[FAN{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if fan_info.get("error"):
                temp = "[API] Get FAN{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                fan_info = None
            else:
                fan_info = unicode_convert(fan_info)
    return {} if not fan_info else fan_info

# 设定指定id风扇的Duty--OEM  id从1开始
def SetFanDutyViaOEM(id,Duty):
    ID = id - 1
    cmd = "{0} {1} 0x0{2} 0x02 {3}".format(IPMITOOL,SET_FAN_OEM,ID,Duty)
    status,output = CMM.run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("FAN {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)

def CheckFanDuty(id,Duty):
    global CASE_PASS
    ID = id - 1
    OEM_info = GetFanInfoViaOEM(id)
    API_info = GetFanInfoViaAPI(CSRFToken,id)
    if OEM_info and API_info:
        temp_list = OEM_info.split()
        OEM_Duty = parse_Duty(temp_list)
        API_Duty = API_info.get("Duty")
        OEM_FanSpeed1 = parse_FanSpeed(temp_list,index=1)
        OEM_FanSpeed2 = parse_FanSpeed(temp_list,index=2)
        API_FanSpeed1 = API_info.get("FanSpeed1")
        API_FanSpeed2 = API_info.get("FanSpeed2")
        FanSpeed = [OEM_FanSpeed1,API_FanSpeed1,OEM_FanSpeed2,API_FanSpeed2]
        if OEM_Duty != Duty or API_Duty != Duty:
            CASE_PASS = False
            fail_text = "FAN{0} Duty should be {1}\n[OEM] Duty: {2}\n[API] Duty: {3}".format(id,Duty,OEM_Duty,API_Duty)
            CMM.save_data(main_log,fail_text,timestamp=False)
            CMM.show_message(fail_text,timestamp=False,color="red")
            return False,FanSpeed
    else:
        CASE_PASS = False
        return False,["Unknown"]*4
    return True,FanSpeed


def parse_id(temp_list):
    try:
        id = int(temp_list[0],16) + 1
    except:
        id = "Unknown"
    return id

def parse_FanStatus(temp_list):
    try:
        FanStatus = int(temp_list[1],16)
    except:
        FanStatus = "Unknown"
    return FanStatus

def parse_Present(temp_list):
    try:
        temp = temp_list[2]
        if temp == "00":
            Present = "N/A"
            FanPresent = int(temp,16)
        elif temp == "01":
            Present = "Present"
            FanPresent = int(temp,16)
        else:
            Present = "Unknown"
            FanPresent = "Unknown"
    except:
        Present = "Unknown"
        FanPresent = "Unknown"
    return Present,FanPresent

def parse_Duty(temp_list):
    try:
        temp = temp_list[3]
        Duty = int(temp,16)
    except:
        Duty = "Unknown"
    return Duty

def parse_FanSpeed(temp_list,index):
    try:
        if index == 1:
            temp = "{0}{1}".format(temp_list[5],temp_list[4])
            FanSpeed = int(temp,16)
        elif index == 2:
            temp = "{0}{1}".format(temp_list[7],temp_list[6])
            FanSpeed = int(temp,16)
        else:
            FanSpeed = "Unknown"
    except:
        FanSpeed = "Unknown"
    return FanSpeed



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
        global LOG_FAIL
        global CSRFToken
        CMM.show_message(format_item("Login Web"),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            message = "[curl] Login Web successfully."
            CMM.save_data(main_log, message)
            CMM.show_message(message)
            CSRFToken = output.strip()
        else:
            CASE_PASS = False
            message = "[curl] Login Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message)
            CMM.show_message(message,color="red")
            MAIN_LOG_list.append("[curl] Login Web FAIL !")
            LOG_FAIL = True

    def c_Check_fan_info(self):
        if LOG_FAIL:
            return False
        global CASE_PASS
        temp_text = "Check fan info"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        for id in range(1,int(FAN_NUM)+1):
            fan = "FAN{0}".format(id)
            is_fail = False
            OEM_info = GetFanInfoViaOEM(id)
            API_info = GetFanInfoViaAPI(CSRFToken,id)
            if OEM_info and API_info:
                temp_list = OEM_info.split()
                # Check FAN id
                OEM_id = parse_id(temp_list)
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(fan,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check FAN Present
                OEM_Present_0,OEM_Present_1 = parse_Present(temp_list)
                API_Present_0 = API_info.get("Present")
                API_Present_1 = API_info.get("FanPresent")
                if OEM_Present_0 != API_Present_0 or OEM_Present_1 != API_Present_1:
                    is_fail = True
                    fail_text = "[OEM] {0} Present: {1}, FanPresent: {2}\n[API] {0} Present: {3}, FanPresent: {4}".format\
                        (fan,OEM_Present_0,OEM_Present_1,API_Present_0,API_Present_1)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                # Check FAN status
                OEM_FanStatus = parse_FanStatus(temp_list)
                API_FanStatus = API_info.get("FanStatus")
                if OEM_FanStatus != API_FanStatus:
                    is_fail = True
                    fail_text = "[OEM] {0} FanStatus: {1}\n[API] {0} FanStatus: {2}".format(fan,OEM_FanStatus,API_FanStatus)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check FAN Duty
                OEM_Duty = parse_Duty(temp_list)
                API_Duty = API_info.get("Duty")
                if OEM_Duty != API_Duty:
                    is_fail = True
                    fail_text = "[OEM] {0} Duty: {1}\n[API] {0} Duty: {2}".format(fan,OEM_Duty,API_Duty)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check FAN FanSpeed
                OEM_FanSpeed1 = parse_FanSpeed(temp_list,index=1)
                OEM_FanSpeed2 = parse_FanSpeed(temp_list,index=2)
                API_FanSpeed1 = API_info.get("FanSpeed1")
                API_FanSpeed2 = API_info.get("FanSpeed2")
                if OEM_FanSpeed1 != API_FanSpeed1 or OEM_FanSpeed2 != API_FanSpeed2:
                    is_fail = True
                    fail_text = "[OEM] {0} FanSpeed: {1} {2}\n[API] {0} FanSpeed: {3} {4}".format\
                        (fan,OEM_FanSpeed1,OEM_FanSpeed2,API_FanSpeed1,API_FanSpeed2)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
            else:
                CASE_PASS = False
                return False
            if is_fail:
                CASE_PASS = False
                temp_text = "[{0}] Check fan info FAIL !".format(fan)
                MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                CMM.show_message(temp_text,timestamp=False,color="red")
            else:
                temp_text = "[{0}] Check fan info PASS.".format(fan)
                CMM.save_data(main_log,temp_text,timestamp=False)
                CMM.show_message(temp_text,timestamp=False)

    def d_set_fan_via_OEM(self):
        global CASE_PASS
        temp_text = "Set fan via OEM command"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        # Switched manual mode
        status, output = CMM.run_cmd(MANUAL_MODE_CMD)
        if status != 0:
            CASE_PASS = False
            fail_text = "[FAIL] Set cooling policy to manual mode."
            MAIN_LOG_list.append(fail_text)
            CMM.save_data(main_log,"{0}\n{1}".format(temp_text,output))
            CMM.show_message(temp_text,timestamp=False,color="red")
            return False
        # Set and check FAN Duty
        Duty_fail = False
        Duty_list = [30,40,50,60,70,80,90,100]
        temp_text = "Set and check FAN Duty: {0}".format(Duty_list)
        CMM.save_data(main_log,temp_text,timestamp=False)
        CMM.show_message(temp_text,timestamp=False,color="blue")
        for id in range(1,int(FAN_NUM)+1):
            for Duty in Duty_list:
                SetFanDutyViaOEM(id,Duty)
                time.sleep(10)
                duty_pass,FanSpeed = CheckFanDuty(id,Duty)
                message = "FAN{0}_Duty{1}:{2}".format(id,Duty,FanSpeed)
                CMM.show_message(message,timestamp=False)
                CMM.save_data(MAIN_LOG,message,timestamp=False)
                if not duty_pass:
                    Duty_fail = True
        if Duty_fail:
            message = "Result: FAIL"
            CMM.show_message(message,timestamp=False,color="red")
        else:
            message = "Result: PASS"
            CMM.show_message(message, timestamp=False)
        CMM.save_data(main_log,message,timestamp=False)
        # Restored auto mode
        status, output = CMM.run_cmd(AUTO_MODE_CMD)
        if status != 0:
            CASE_PASS = False
            fail_text = "[FAIL] Set cooling policy to auto mode."
            MAIN_LOG_list.append(fail_text)
            CMM.save_data(main_log,"{0}\n{1}".format(temp_text,output))
            CMM.show_message(temp_text,timestamp=False,color="red")
            return False

    # TODO: Set fan via Web API
    # def f_set_fan_via_API(self):
    #     global CASE_PASS
    #     temp_text = "Set fan via Web API"
    #     CMM.show_message(format_item(temp_text), color="green", timestamp=False)
    #     CMM.save_data(main_log, temp_text, timestamp=False)






    def g_curl_logout(self):
        if LOG_FAIL:
            return False
        CMM.show_message(format_item("Logout Web"),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
        if status == 0:
            message = "[curl] Logout Web successfully."
            CMM.save_data(main_log, message)
            CMM.show_message(message)
        else:
            message = "[curl] Logout Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message)
            CMM.show_message(message,color="red")

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