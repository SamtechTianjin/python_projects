# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import json
import re
import random
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
PSU_NUM = config.PSU_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_PSU_API = "/api/cmminfo/psus"
GET_PSU_OEM = "raw 0x3a 0x51"
SET_PSU_API = "raw 0x3a 0x50"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

Present_psu = []

"""
API接口返回值:
Vendor,Vout,Pin,Pout,Iout,Vin,isPSUOn,Temp2,Temp1,Fan1Speed,SN,psuPresent,Model,Iin,FanDuty,id,Present
"""

# 获得指定id的电源信息--OEM  id从1开始
def GetPSUInfoViaOEM(id):
    cmd_id = id - 1
    PSU_info = None
    cmd = "{0} {1} 0x0{2} 2>/dev/null".format(IPMITOOL,GET_PSU_OEM,cmd_id)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("PSU {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[OEM] Get PSU{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        PSU_info = output
    return "" if not PSU_info else PSU_info

# 获得指定id的电源信息--API  id从1开始
def GetPSUInfoViaAPI(CSRFToken,id):
    PSU_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_PSU_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("PSU {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get PSU{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            PSU_info = json.loads(output.strip())
        except Exception as e:
            temp = "[PSU{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
            MAIN_LOG_list.append(temp)
        else:
            if PSU_info.get("error"):
                temp = "[API] Get PSU{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                PSU_info = None
            else:
                PSU_info = unicode_convert(PSU_info)
    return {} if not PSU_info else PSU_info

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
        # FanDuty = int(temp_list[65],16)
        FanDuty = int(temp_list[77],16)
    except:
        FanDuty = "Unknown"
    return FanDuty

def parse_Iin(temp_list):
    try:
        # Iin = int(temp_list[64],16)
        Iin = int(temp_list[76],16)
    except:
        Iin = "Unknown"
    return Iin

def parse_Iout(temp_list):
    try:
        # Iout = int(temp_list[63],16)
        Iout = int(temp_list[75],16)
    except:
        Iout = "Unknown"
    return Iout

def parse_Vin(temp_list):
    try:
        # Vin = int(temp_list[62],16)
        Vin = int(temp_list[74],16)
    except:
        Vin = "Unknown"
    return Vin

def parse_Vout(temp_list):
    try:
        # Vout = int(temp_list[61],16)
        Vout = int(temp_list[73],16)
    except:
        Vout = "Unknown"
    return Vout

def parse_Pin(temp_list):
    try:
        # temp1 = int(temp_list[60],16)*256
        temp1 = int(temp_list[72],16)*256
        # temp2 = int(temp_list[59],16)
        temp2 = int(temp_list[71],16)
        Pin = temp1 + temp2
    except:
        Pin = "Unknown"
    return Pin

def parse_Pout(temp_list):
    try:
        # temp1 = int(temp_list[58],16)*256
        temp1 = int(temp_list[70],16)*256
        # temp2 = int(temp_list[57],16)
        temp2 = int(temp_list[69],16)
        Pout = temp1 + temp2
    except:
        Pout = "Unknown"
    return Pout

def parse_Temp(temp_list):
    try:
        # Temp1 = int(temp_list[53],16)
        Temp1 = int(temp_list[65],16)
        # Temp2 = int(temp_list[54],16)
        Temp2 = int(temp_list[66],16)
    except:
        Temp1 = "Unknown"
        Temp2 = "Unknown"
    return Temp1,Temp2

def parse_Fan1Speed(temp_list):
    try:
        # temp1 = int(temp_list[56],16)*256
        temp1 = int(temp_list[68],16)*256
        # temp2 = int(temp_list[55],16)
        temp2 = int(temp_list[67],16)
        Fan1Speed = temp1 + temp2
    except:
        Fan1Speed = "Unknown"
    return Fan1Speed

def parse_SN(temp_list):
    try:
        SN = ""
        # temp_list = temp_list[37:53]
        temp_list = temp_list[45:65]
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
        # temp_list = temp_list[21:37]
        temp_list = temp_list[25:45]
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
        # temp_list = temp_list[5:21]
        temp_list = temp_list[5:25]
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

def set_psu_powerstate_via_API(psu_id):
    # 执行命令后等待时间
    waitTime = 60
    is_fail = False
    restapi = "/api/cmmstate/psus"
    poweroff_cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'id':%s,'controlcommand':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,psu_id,IP,restapi)
    poweron_cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'id':%s,'controlcommand':1}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,psu_id,IP,restapi)
    initial_power = GetPSUInfoViaAPI(CSRFToken, psu_id).get("isPSUOn")
    # 初始化电源状态为ON
    if initial_power == "OFF":
        status,output = CMM.retry_run_cmd(poweron_cmd)
        message = "Init psu{0} power state\n{1}\nreturncode: {2}\n{3}".format(psu_id,poweron_cmd,status,output)
        CMM.save_data(main_log, message, timestamp=False)
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_fail = True
            message = "[Exception] {0}".format(e)
            CMM.show_message(message,timestamp=False,color="red")
            CMM.save_data(main_log,message,timestamp=False)
        else:
            if json_data.get("error"):
                is_fail = True
                MAIN_LOG_list.append(output)
                CMM.show_message(output,timestamp=False,color="red")
        time.sleep(waitTime)
    # 确认电源状态为ON 否则退出测试
    initial_power = GetPSUInfoViaAPI(CSRFToken, psu_id).get("isPSUOn")
    if initial_power == "ON":
        # 首先设置电源状态为OFF
        status, output = CMM.retry_run_cmd(poweroff_cmd)
        message = "Set psu{0} power off\n{1}\nreturncode: {2}\n{3}".format(psu_id, poweroff_cmd, status, output)
        CMM.save_data(main_log, message, timestamp=False)
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_fail = True
            message = "[Exception] {0}".format(e)
            CMM.show_message(message, timestamp=False, color="red")
            CMM.save_data(main_log, message, timestamp=False)
        else:
            if json_data.get("error"):
                is_fail = True
                MAIN_LOG_list.append(output)
                CMM.show_message(output, timestamp=False, color="red")
        time.sleep(waitTime)
        current_power_API_1 = GetPSUInfoViaAPI(CSRFToken, psu_id).get("isPSUOn")
        temp = GetPSUInfoViaOEM(psu_id)
        current_power_OEM_1 = parse_isPSUOn(temp.split())
        if current_power_API_1 != "OFF" or current_power_OEM_1 != "OFF":
            is_fail = True
            temp_text = "[PSU{0}] Expect power state: {1}".format(psu_id, "OFF")
            CMM.show_message(temp_text, timestamp=False, color="red")
            MAIN_LOG_list.append(temp_text)
            temp_text = "[PSU{0}] Current power state: OEM {1}, API {2}".format(psu_id, current_power_OEM_1,current_power_API_1)
            CMM.show_message(temp_text, timestamp=False, color="red")
            MAIN_LOG_list.append(temp_text)
        else:
            # 然后设置电源状态为ON
            status, output = CMM.retry_run_cmd(poweron_cmd)
            message = "Set psu{0} power on\n{1}\nreturncode: {2}\n{3}".format(psu_id, poweron_cmd, status, output)
            CMM.save_data(main_log, message, timestamp=False)
            try:
                json_data = json.loads(output)
            except Exception as e:
                is_fail = True
                message = "[Exception] {0}".format(e)
                CMM.show_message(message, timestamp=False, color="red")
                CMM.save_data(main_log, message, timestamp=False)
            else:
                if json_data.get("error"):
                    is_fail = True
                    MAIN_LOG_list.append(output)
                    CMM.show_message(output, timestamp=False, color="red")
            time.sleep(waitTime)
            current_power_API_2 = GetPSUInfoViaAPI(CSRFToken, psu_id).get("isPSUOn")
            temp = GetPSUInfoViaOEM(psu_id)
            current_power_OEM_2 = parse_isPSUOn(temp.split())
            if current_power_API_2 != "ON" or current_power_OEM_2 != "ON":
                is_fail = True
                temp_text = "[PSU{0}] Expect power state: {1}".format(psu_id, "ON")
                CMM.show_message(temp_text, timestamp=False, color="red")
                MAIN_LOG_list.append(temp_text)
                temp_text = "[PSU{0}] Current power state: OEM {1}, API {2}".format(psu_id, current_power_OEM_2,current_power_API_2)
                CMM.show_message(temp_text, timestamp=False, color="red")
                MAIN_LOG_list.append(temp_text)
    else:
        is_fail = True
    return False if is_fail else True

def set_psu_fanduty_via_API(psu_id):
    # 执行命令后等待时间
    waitTime = 60
    is_fail = False
    duty = random.randint(30,100)
    restapi = "/api/cmmstate/psus"
    set_cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'id':%s,'controlcommand':2,'parameter':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,psu_id,duty,IP,restapi)
    status,output = CMM.retry_run_cmd(set_cmd)
    message = "Set psu{0} duty\n{1}\nreturncode: {2}\n{3}".format(psu_id,set_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    try:
        json_data = json.loads(output)
    except Exception as e:
        is_fail = True
        message = "[Exception] {0}".format(e)
        MAIN_LOG_list.append(message)
        CMM.show_message(message,timestamp=False,color="red")
        CMM.save_data(main_log,message,timestamp=False)
    else:
        if json_data.get("error"):
            is_fail = True
            MAIN_LOG_list.append(output)
            CMM.show_message(output,timestamp=False,color="red")
    time.sleep(waitTime)
    current_duty_API = GetPSUInfoViaAPI(CSRFToken,psu_id).get("FanDuty")
    temp = GetPSUInfoViaOEM(psu_id)
    current_duty_OEM = parse_FanDuty(temp.split())
    if current_duty_API != duty or current_duty_OEM != duty:
        is_fail = True
        temp_text = "[PSU{0}] Set fan duty: {1}".format(psu_id,duty)
        CMM.show_message(temp_text,timestamp=False,color="red")
        MAIN_LOG_list.append(temp_text)
        temp_text = "[PSU{0}] Get fan duty: OEM {1}, API {2}".format(psu_id,current_duty_OEM,current_duty_API)
        CMM.show_message(temp_text,timestamp=False,color="red")
        MAIN_LOG_list.append(temp_text)
    return False if is_fail else True

def getAllPsus():
    data = []
    restapi = "/api/cmmpower/allpsus"
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "Collect all psu pout\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            CMM.save_data(main_log,message,timestamp=False)
        else:
            if isinstance(json_data,dict) and json_data.get("error"):
                MAIN_LOG_list.append("{0}".format(json_data))
                CMM.show_message("{0}".format(json_data),timestamp=False,color="red")
            else:
                data = json_data
    return data




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

    def c_check_psu_info(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        global Present_psu
        temp_text = "Check PSU info"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        id_list,Present_list,FanDuty_list,isPSUOn_list,SN_list,Model_list,Vendor_list = [],[],[],[],[],[],[]
        for id in range(1,int(PSU_NUM)+1):
            psu = "PSU{0}".format(id)
            is_fail = False
            OEM_info = GetPSUInfoViaOEM(id)
            API_info = GetPSUInfoViaAPI(CSRFToken,id)
            if API_info.get("psuPresent") == 1:
                Present_psu.append(id)
            CMM.save_data(MAIN_LOG,"PSU_API_{0}:{1}".format(id,API_info),timestamp=False)
            if OEM_info or API_info:
                OEM_dict_info = {}
                temp_list = OEM_info.split()
                # Check PSU id
                message = "- Check PSU id -"
                if message not in id_list:
                    id_list.append(message)
                OEM_id = parse_id(temp_list)
                OEM_dict_info["id"] = OEM_id
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(psu,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    id_list.append("[OEM] {0} id: {1}".format(psu,OEM_id))
                    id_list.append("[API] {0} id: {1}".format(psu,API_id))
                # Check PSU Present
                message = "- Check PSU Present -"
                if message not in Present_list:
                    Present_list.append(message)
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
                    Present_list.append("[OEM] {0} Present: {1}, psuPresent: {2}".format(psu,OEM_Present_0,OEM_Present_1))
                    Present_list.append("[API] {0} Present: {1}, psuPresent: {2}".format(psu,API_Present_0,API_Present_1))
                # Check PSU FanDuty
                message = "- Check PSU FanDuty -"
                if message not in FanDuty_list:
                    FanDuty_list.append(message)
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
                        FanDuty_list.append("[OEM] {0} FanDuty: {1}".format(psu,OEM_FanDuty))
                        FanDuty_list.append("[API] {0} FanDuty: {1}".format(psu,API_FanDuty))
                # Check PSU isPSUOn
                message = "- Check PSU isPSUOn -"
                if message not in isPSUOn_list:
                    isPSUOn_list.append(message)
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
                        isPSUOn_list.append("[OEM] {0} isPSUOn: {1}".format(psu,OEM_isPSUOn))
                        isPSUOn_list.append("[API] {0} isPSUOn: {1}".format(psu,API_isPSUOn))
                # Check PSU SN
                message = "- Check PSU SN -"
                if message not in SN_list:
                    SN_list.append(message)
                OEM_SN = parse_SN(temp_list)
                OEM_dict_info["SN"] = OEM_SN
                API_SN = API_info.get("SN")
                if OEM_SN != API_SN:
                    is_fail = True
                    fail_text = "[OEM] {0} SN: {1}\n[API] {0} SN: {2}".format(psu, OEM_SN, API_SN)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                    SN_list.append("[OEM] {0} SN: {1}".format(psu,OEM_SN))
                    SN_list.append("[API] {0} SN: {1}".format(psu,API_SN))
                # Check PSU Model
                message = "- Check PSU Model -"
                if message not in Model_list:
                    Model_list.append(message)
                OEM_Model = parse_Model(temp_list)
                OEM_dict_info["Model"] = OEM_Model
                API_Model = API_info.get("Model")
                if OEM_Model != API_Model:
                    is_fail = True
                    fail_text = "[OEM] {0} Model: {1}\n[API] {0} Model: {2}".format(psu, OEM_Model, API_Model)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                    Model_list.append("[OEM] {0} Model: {1}".format(psu,OEM_Model))
                    Model_list.append("[API] {0} Model: {1}".format(psu,API_Model))
                # Check PSU Vendor
                message = "- Check PSU Vendor -"
                if message not in Vendor_list:
                    Vendor_list.append(message)
                OEM_Vendor = parse_Vendor(temp_list)
                OEM_dict_info["Vendor"] = OEM_Vendor
                API_Vendor = API_info.get("Vendor")
                if OEM_Vendor != API_Vendor:
                    is_fail = True
                    fail_text = "[OEM] {0} Vendor: {1}\n[API] {0} Vendor: {2}".format(psu, OEM_Vendor, API_Vendor)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                    Vendor_list.append("[OEM] {0} Vendor: {1}".format(psu,OEM_Vendor))
                    Vendor_list.append("[API] {0} Vendor: {1}".format(psu,API_Vendor))
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
                is_fail = True
            if is_fail:
                CASE_PASS = False
                temp_text = "[{0}] Check PSU info FAIL !".format(psu)
                # MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check PSU info".format(psu),flag="FAIL")
            else:
                temp_text = "[{0}] Check PSU info PASS.".format(psu)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check PSU info".format(psu),flag="PASS")
        for l in [id_list,Present_list,FanDuty_list,isPSUOn_list,SN_list,Model_list,Vendor_list]:
            for item in l:
                MAIN_LOG_list.append(item)

    def d_check_all_psu_pout_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        is_FAIL = False
        temp_text = "- Check all psu pout via API -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        json_data = getAllPsus()
        if json_data:
            if len(json_data) != PSU_NUM:
                is_FAIL = True
                MAIN_LOG_list.append("{0}".format(json_data))
                CMM.show_message("{0}".format(json_data),timestamp=False,color="red")
            else:
                for psu_id in range(1,PSU_NUM+1):
                    API_info = GetPSUInfoViaAPI(CSRFToken,psu_id)
                    expect_pout = API_info.get("Pout")
                    if not API_info:
                        is_FAIL = True
                    for item in json_data:
                        get_id = item.get("id")
                        if get_id == psu_id:
                            get_pout = item.get("Pout")
                            if get_id in Present_psu:
                                temp_pout = abs(int(get_pout)-int(expect_pout))
                                if temp_pout > int(expect_pout)/3:
                                    is_FAIL = True
                                    text = "[/cmminfo/psus] PSU{0} {1}".format(psu_id,expect_pout)
                                    MAIN_LOG_list.append(text)
                                    CMM.show_message(text,timestamp=False,color="red")
                                    CMM.save_data(main_log,text,timestamp=False)
                                    text = "[/cmmpower/allpsus] PSU{0} {1}".format(psu_id,get_pout)
                                    MAIN_LOG_list.append(text)
                                    CMM.show_message(text,timestamp=False,color="red")
                                    CMM.save_data(main_log,text,timestamp=False)
                            else:
                                if get_pout != "":
                                    is_FAIL = True
                                    text = "[PSU{0}] {1}".format(psu_id,get_pout)
                                    MAIN_LOG_list.append(text)
                                    CMM.show_message(text,timestamp=False,color="red")
                            break
                    else:
                        is_FAIL = True
        else:
            is_FAIL = True
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message, flag="FAIL")
            CMM.save_step_result(main_log, message, flag="FAIL")
        else:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log, message, flag="PASS")


    # TODO: Set PSU via OEM command

    def m_set_psu_power_state_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set psu power state via API -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for psu_id in range(1, int(PSU_NUM) + 1):
            if psu_id not in Present_psu:
                continue
            status = set_psu_powerstate_via_API(psu_id)
            message = "[PSU{0}] {1}".format(psu_id,temp_text.strip(" -"))
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def n_set_psu_fanduty_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set psu fan duty via API -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for psu_id in range(1, int(PSU_NUM) + 1):
            if psu_id not in Present_psu:
                continue
            status = set_psu_fanduty_via_API(psu_id)
            message = "[PSU{0}] {1}".format(psu_id,temp_text.strip(" -"))
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

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