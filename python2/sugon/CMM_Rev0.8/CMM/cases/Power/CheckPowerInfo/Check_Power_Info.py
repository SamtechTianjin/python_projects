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
POWER_NUM = config.POWER_NUM

# Global variable
LOG_FAIL = False
CSRFToken = ""
GET_POWER_API = "/api/cmminfo/psus/"
GET_POWER_OEM = "raw 0x3a 0x51"
SET_POWER_OEM = "raw 0x3a 0x50"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
API接口返回值:
Vendor,Vout,Pin,Pout,Iout,Vin,isPSUOn,Temp2,Temp1,Fan1Speed,SN,psuPresent,Model,Iin,FanDuty,id,Present
"""

# 获得指定id的电源信息--OEM  id从1开始
def GetPowerInfoViaOEM(id):
    cmd_id = id - 1
    power_info = None
    cmd = "{0} {1} 0x0{2} 2>/dev/null".format(IPMITOOL,GET_POWER_OEM,cmd_id)
    status,output = CMM.run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("PSU {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[OEM] Get PSU{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        power_info = output
    return "" if not power_info else power_info

# 获得指定id的电源信息--API  id从1开始
def GetPowerInfoViaAPI(CSRFToken,id):
    power_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d\"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_POWER_API)
    status,output = CMM.run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("PSU {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)

    if status != 0:
        temp = "[API] Get PSU{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            power_info = json.loads(output.strip())
        except Exception as e:
            temp = "[PSU{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if power_info.get("error"):
                temp = "[API] Get PSU{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                power_info = None
            else:
                power_info = unicode_convert(power_info)
    return {} if not power_info else power_info

def parse_id(temp_list):
    try:
        id = int(temp_list[0],16) + 1
    except:
        id = "Unknown"
    return id

def parse_Present(temp_list):
    try:
        temp = temp_list[1]
        if temp == "00":
            Present = "N/A"
            psuPresent = int(temp,16)
        elif temp == "01":
            Present = "Present"
            psuPresent = int(temp, 16)
        else:
            Present = "Unknown"
            psuPresent = "Unknown"
    except:
        Present = "Unknown"
        psuPresent = "Unknown"
    return Present,psuPresent






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

    def c_Check_power_info(self):
        if LOG_FAIL:
            return False
        global CASE_PASS
        temp_text = "Check power info"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        for id in range(1,int(POWER_NUM)+1):
            psu = "PSU{0}".format(id)
            is_fail = False
            OEM_info = GetPowerInfoViaOEM(id)
            API_info = GetPowerInfoViaAPI(CSRFToken,id)
            CMM.save_data(MAIN_LOG,"PSU_OEM_{2}:{0}\nPSU_API_{2}:{1}".format(OEM_info,API_info,id),timestamp=False)
            if OEM_info and API_info:
                temp_list = OEM_info.split()
                # Check PSU id
                OEM_id = parse_id(temp_list)
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(psu,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check PSU Present
                OEM_Present_0,OEM_Present_1 = parse_Present(temp_list)
                API_Present_0 = API_info.get("Present")
                API_Present_1 = API_info.get("psuPresent")
                if OEM_Present_0 != API_Present_0 or OEM_Present_1 != API_Present_1:
                    is_fail = True
                    fail_text = "[OEM] {0} Present: {1}, psuPresent: {2}\n[API] {0} Present: {3}, psuPresent: {4}".format\
                        (psu, OEM_Present_0, OEM_Present_1, API_Present_0, API_Present_1)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
            else:
                CASE_PASS = False
                return False
            if is_fail:
                CASE_PASS = False
                temp_text = "[{0}] Check power info FAIL !".format(psu)
                MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                CMM.show_message(temp_text,timestamp=False,color="red")
            else:
                temp_text = "[{0}] Check power info PASS.".format(psu)
                CMM.save_data(main_log,temp_text,timestamp=False)
                CMM.show_message(temp_text,timestamp=False)

    # TODO: Set power via OEM command | Web API
    def d_set_power_via_OEM(self):
        global CASE_PASS
        temp_text = "Set power via OEM command"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)

    def f_set_power_via_API(self):
        global CASE_PASS
        temp_text = "Set power via Web API"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)






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