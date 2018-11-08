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
    status,output = CMM.retry_run_cmd(cmd)
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
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_POWER_API)
    status,output = CMM.retry_run_cmd(cmd)
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

def parse_FanDuty(temp_list):
    try:
        FanDuty = int(temp_list[65],16)
    except:
        FanDuty = "Unknown"
    return FanDuty

def parse_Iin(temp_list):
    try:
        Iin = int(temp_list[64],16)
    except:
        Iin = "Unknown"
    return Iin

def parse_Iout(temp_list):
    try:
        Iout = int(temp_list[63],16)
    except:
        Iout = "Unknown"
    return Iout

def parse_Vin(temp_list):
    try:
        Vin = int(temp_list[62],16)
    except:
        Vin = "Unknown"
    return Vin

def parse_Vout(temp_list):
    try:
        Vout = int(temp_list[61],16)
    except:
        Vout = "Unknown"
    return Vout

def parse_Pin(temp_list):
    try:
        temp1 = int(temp_list[60],16)*256
        temp2 = int(temp_list[59],16)
        Pin = temp1 + temp2
    except:
        Pin = "Unknown"
    return Pin

def parse_Pout(temp_list):
    try:
        temp1 = int(temp_list[58],16)*256
        temp2 = int(temp_list[57],16)
        Pout = temp1 + temp2
    except:
        Pout = "Unknown"
    return Pout

def parse_Temp(temp_list):
    try:
        Temp1 = int(temp_list[53],16)
        Temp2 = int(temp_list[54],16)
    except:
        Temp1 = "Unknown"
        Temp2 = "Unknown"
    return Temp1,Temp2

def parse_Fan1Speed(temp_list):
    try:
        temp1 = int(temp_list[56],16)*256
        temp2 = int(temp_list[55],16)
        Fan1Speed = temp1 + temp2
    except:
        Fan1Speed = "Unknown"
    return Fan1Speed

def parse_SN(temp_list):
    try:
        SN = ""
        temp_list = temp_list[37:53]
        for temp in temp_list:
            if temp == "00":
                break
            temp = chr(int(temp,16))
            SN += temp
    except:
        SN = "Unknown"
    return SN

def parse_Model(temp_list):
    try:
        Model = ""
        temp_list = temp_list[21:37]
        for temp in temp_list:
            if temp == "00":
                break
            temp = chr(int(temp,16))
            Model += temp
    except:
        Model = "Unknown"
    return Model

def parse_Vendor(temp_list):
    try:
        Vendor = ""
        temp_list = temp_list[5:21]
        for temp in temp_list:
            if temp == "00":
                break
            temp = chr(int(temp,16))
            Vendor += temp
    except:
        Vendor = "Unknown"
    return Vendor

def parse_isPSUOn(temp_list):
    try:
        temp = temp_list[4]
        if temp == "00":
            isPSUOn = "OFF"
        elif temp == "01":
            isPSUOn = "ON"
        else:
            isPSUOn = "Unknown"
    except:
        isPSUOn = "Unknown"
    return isPSUOn




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
            show_step_result("[curl] Login Web", flag="PASS")
            CSRFToken = output.strip()
        else:
            CASE_PASS = False
            message = "[curl] Login Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message)
            show_step_result("[curl] Login Web", flag="FAIL")
            MAIN_LOG_list.append("[curl] Login Web FAIL !")
            LOG_FAIL = True

    def c_check_power_info(self):
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
            CMM.save_data(MAIN_LOG,"PSU_API_{0}:{1}".format(id,API_info),timestamp=False)
            if OEM_info or API_info:
                OEM_dict_info = {}
                temp_list = OEM_info.split()
                # Check PSU id
                OEM_id = parse_id(temp_list)
                OEM_dict_info["id"] = OEM_id
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(psu,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check PSU Present
                OEM_Present_0,OEM_Present_1 = parse_Present(temp_list)
                OEM_dict_info["psuPresent"] = OEM_Present_1
                API_Present_0 = API_info.get("Present")
                API_Present_1 = API_info.get("psuPresent")
                if OEM_Present_0 != API_Present_0 or OEM_Present_1 != API_Present_1:
                    is_fail = True
                    fail_text = "[OEM] {0} Present: {1}, psuPresent: {2}\n[API] {0} Present: {3}, psuPresent: {4}".format\
                        (psu, OEM_Present_0, OEM_Present_1, API_Present_0, API_Present_1)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                # Check PSU FanDuty
                OEM_FanDuty = parse_FanDuty(temp_list)
                OEM_dict_info["FanDuty"] = OEM_FanDuty
                API_FanDuty = API_info.get("FanDuty")
                if OEM_FanDuty != API_FanDuty:
                    """ 考虑PSU不在位情况 """
                    if OEM_Present_1 == 1 or API_Present_1 == 1:
                        is_fail = True
                        fail_text = "[OEM] {0} FanDuty: {1}\n[API] {0} FanDuty: {2}".format(psu,OEM_FanDuty,API_FanDuty)
                        CMM.save_data(main_log, fail_text, timestamp=False)
                        CMM.show_message(fail_text, timestamp=False)
                # Check PSU isPSUOn
                OEM_isPSUOn = parse_isPSUOn(temp_list)
                OEM_dict_info["isPSUOn"] = OEM_isPSUOn
                API_isPSUOn = API_info.get("isPSUOn")
                if OEM_isPSUOn != API_isPSUOn:
                    """ 考虑PSU不在位情况 """
                    if OEM_Present_1 == 1 or API_Present_1 == 1:
                        is_fail = True
                        fail_text = "[OEM] {0} isPSUOn: {1}\n[API] {0} isPSUOn: {2}".format(psu, OEM_isPSUOn, API_isPSUOn)
                        CMM.save_data(main_log, fail_text, timestamp=False)
                        CMM.show_message(fail_text, timestamp=False)
                # Check PSU SN
                OEM_SN = parse_SN(temp_list)
                OEM_dict_info["SN"] = OEM_SN
                API_SN = API_info.get("SN")
                if OEM_SN != API_SN:
                    is_fail = True
                    fail_text = "[OEM] {0} SN: {1}\n[API] {0} SN: {2}".format(psu, OEM_SN, API_SN)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                # Check PSU Model
                OEM_Model = parse_Model(temp_list)
                OEM_dict_info["Model"] = OEM_Model
                API_Model = API_info.get("Model")
                if OEM_Model != API_Model:
                    is_fail = True
                    fail_text = "[OEM] {0} Model: {1}\n[API] {0} Model: {2}".format(psu, OEM_Model, API_Model)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                # Check PSU Vendor
                OEM_Vendor = parse_Vendor(temp_list)
                OEM_dict_info["Vendor"] = OEM_Vendor
                API_Vendor = API_info.get("Vendor")
                if OEM_Vendor != API_Vendor:
                    is_fail = True
                    fail_text = "[OEM] {0} Vendor: {1}\n[API] {0} Vendor: {2}".format(psu, OEM_Vendor, API_Vendor)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                """ 电流 功耗 电压 风扇转速 电源温度 仅仅打印到PDF表格 不作比较 """
                # Check PSU Iin
                OEM_Iin = parse_Iin(temp_list)
                OEM_dict_info["Iin"] = OEM_Iin
                # Check PSU Iout
                OEM_Iout = parse_Iout(temp_list)
                OEM_dict_info["Iout"] = OEM_Iout
                # Check PSU Pin
                OEM_Pin = parse_Pin(temp_list)
                OEM_dict_info["Pin"] = OEM_Pin
                # Check PSU Pout
                OEM_Pout = parse_Pout(temp_list)
                OEM_dict_info["Pout"] = OEM_Pout
                # Check PSU Vin
                OEM_Vin = parse_Vin(temp_list)
                OEM_dict_info["Vin"] = OEM_Vin
                # Check PSU Vout
                OEM_Vout = parse_Vout(temp_list)
                OEM_dict_info["Vout"] = OEM_Vout
                # Check PSU Temp
                OEM_Temp1,OEM_Temp2 = parse_Temp(temp_list)
                OEM_dict_info["Temp1"] = OEM_Temp1
                OEM_dict_info["Temp2"] = OEM_Temp2
                # Check PSU FanSpeed
                OEM_Fan1Speed = parse_Fan1Speed(temp_list)
                OEM_dict_info["Fan1Speed"] = OEM_Fan1Speed
                CMM.save_data(MAIN_LOG, "PSU_OEM_{0}:{1}".format(id, OEM_dict_info), timestamp=False)
            else:
                CASE_PASS = False
            if is_fail or not CASE_PASS:
                CASE_PASS = False
                temp_text = "[{0}] Check power info FAIL !".format(psu)
                MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check power info".format(psu),flag="FAIL")
            else:
                temp_text = "[{0}] Check power info PASS.".format(psu)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check power info".format(psu),flag="PASS")

    def d_check_power_parameter_selector(self):
        pass

    # TODO: Set power via OEM command
    # def d_set_power_via_OEM(self):
    #     global CASE_PASS
    #     temp_text = "Set power via OEM command"
    #     CMM.show_message(format_item(temp_text), color="green", timestamp=False)
    #     CMM.save_data(main_log, temp_text, timestamp=False)

    # TODO: Set power via Web API
    # def f_set_power_via_API(self):
    #     global CASE_PASS
    #     temp_text = "Set power via Web API"
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
            show_step_result("[curl] Logout Web",flag="PASS")
        else:
            message = "[curl] Logout Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message)
            show_step_result("[curl] Logout Web",flag="FAIL")

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