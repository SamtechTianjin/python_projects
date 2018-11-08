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
SWITCH_NUM = config.SWITCH_NUM

# Global variable
LOG_FAIL = False
CSRFToken = ""
GET_SWITCH_API = "/api/cmminfo/switches/"
GET_SWITCH_OEM = "raw 0x3a 0x5f"
SET_SWITCH_OEM = "raw 0x3a 0x5e"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
API接口返回值:
id,swPresent,Present,Status,Vendor,SwitchType,Temperature,Pwr_consump,IP,Netmask,Gateway
"""

# 获得指定id的风扇信息--OEM  id从1开始
def GetSwitchInfoViaOEM(id):
    cmd_id = id - 1
    switch_info = None
    cmd = "{0} {1} 0x0{2} 2>/dev/null".format(IPMITOOL,GET_SWITCH_OEM,cmd_id)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("Switch {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[OEM] Get Switch{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        switch_info = output
    return "" if not switch_info else switch_info

# 获得指定id的风扇信息--API  id从1开始
def GetSwitchInfoViaAPI(CSRFToken,id):
    switch_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_SWITCH_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("Switch {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get Switch{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            switch_info = json.loads(output.strip())
            if isinstance(switch_info,list):
                switch_info = switch_info[0]
        except Exception as e:
            temp = "[Switch{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if switch_info.get("error"):
                temp = "[API] Get Switch{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                switch_info = None
            else:
                switch_info = unicode_convert(switch_info)
    return {} if not switch_info else switch_info

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
            swPresent = int(temp,16)
        elif temp == "01":
            Present = "Present"
            swPresent = int(temp,16)
        else:
            Present = "Unknown"
            swPresent = "Unknown"
    except:
        Present = "Unknown"
        swPresent = "Unknown"
    return Present,swPresent

def parse_Status(temp_list):
    try:
        temp = int(temp_list[2],16)
        if temp == 1:
            Status = "Power Off"
        elif temp == 2:
            Status = "Power On"
        elif temp == 3:
            Status = "Over Temp"
        elif temp == 7:
            Status = "Communication Lost"
        elif temp == 0:
            Status = ""
        else:
            Status = "Unknown"
    except:
        Status = "Unknown"
    return Status

def parse_Vendor(temp_list):
    try:
        Vendor = ""
        for temp in temp_list[3:19]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            Vendor += string
    except:
        Vendor = "Unknown"
    return Vendor

def parse_SwitchType(temp_list):
    try:
        temp = temp_list[19]
        if temp == "11":
            SwitchType = "Ethernet Switch"
        elif temp == "12":
            SwitchType = "Fibre Channel Switch"
        elif temp == "14":
            SwitchType = "Infiniband Switch"
        elif temp == "00":
            SwitchType = ""
        else:
            SwitchType = "Unknown"
    except:
        SwitchType = "Unknown"
    return SwitchType

def parse_Temperature(temp_list):
    try:
        Temperature = int(temp_list[20],16)
        if Temperature == 0:
            Temperature = ""
    except:
        Temperature = "Unknown"
    return Temperature

def parse_Pwr_consump(temp_list):
    try:
        Pwr_consump = int(temp_list[21],16)
        if Pwr_consump == 0:
            Pwr_consump = ""
    except:
        Pwr_consump = "Unknown"
    return Pwr_consump

def parse_IP(temp_list):
    try:
        temp1 = int(temp_list[22],16)
        temp2 = int(temp_list[23],16)
        temp3 = int(temp_list[24],16)
        temp4 = int(temp_list[25],16)
        IP = "{0}.{1}.{2}.{3}".format(temp1,temp2,temp3,temp4)
        if IP == "0.0.0.0":
            IP = ""
    except:
        IP = "Unknown"
    return IP

def parse_Netmask(temp_list):
    try:
        temp1 = int(temp_list[26],16)
        temp2 = int(temp_list[27],16)
        temp3 = int(temp_list[28],16)
        temp4 = int(temp_list[29],16)
        NetMask = "{0}.{1}.{2}.{3}".format(temp1,temp2,temp3,temp4)
        if NetMask == "0.0.0.0":
            NetMask = ""
    except:
        NetMask = "Unknown"
    return NetMask

def parse_Gateway(temp_list):
    try:
        temp1 = int(temp_list[30],16)
        temp2 = int(temp_list[31],16)
        temp3 = int(temp_list[32],16)
        temp4 = int(temp_list[33],16)
        Gateway = "{0}.{1}.{2}.{3}".format(temp1,temp2,temp3,temp4)
        if Gateway == "0.0.0.0":
            Gateway = ""
    except:
        Gateway = "Unknown"
    return Gateway




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

    def c_Check_switch_info(self):
        if LOG_FAIL:
            return False
        global CASE_PASS
        temp_text = "Check switch info"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        for id in range(1,int(SWITCH_NUM)+1):
            switch = "Switch{0}".format(id)
            is_fail = False
            OEM_info = GetSwitchInfoViaOEM(id)
            API_info = GetSwitchInfoViaAPI(CSRFToken,id)
            if OEM_info and API_info:
                temp_list = OEM_info.split()
                # Check Switch id
                OEM_id = parse_id(temp_list)
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(switch,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Present
                OEM_Present_0,OEM_Present_1 = parse_Present(temp_list)
                API_Present_0 = API_info.get("Present")
                # 兼容Present前面多出空格 更改后注释掉
                if API_Present_0 == None:
                    API_Present_0 = API_info.get(" Present")
                API_Present_1 = API_info.get("swPresent")
                if OEM_Present_0 != API_Present_0 or OEM_Present_1 != API_Present_1:
                    is_fail = True
                    fail_text = "[OEM] {0} Present: {1}, swPresent: {2}\n[API] {0} Present: {3}, swPresent: {4}".format\
                        (switch,OEM_Present_0,OEM_Present_1,API_Present_0,API_Present_1)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                # Check Switch Status
                OEM_Status = parse_Status(temp_list)
                API_Status = API_info.get("Status")
                if OEM_Status != API_Status:
                    is_fail = True
                    fail_text = "[OEM] {0} Status: {1}\n[API] {0} Status: {2}".format(switch,OEM_Status,API_Status)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Vendor
                OEM_Vendor = parse_Vendor(temp_list)
                API_Vendor = API_info.get("Vendor")
                if OEM_Vendor != API_Vendor:
                    is_fail = True
                    fail_text = "[OEM] {0} Vendor: {1}\n[API] {0} Vendor: {2}".format(switch,OEM_Vendor,API_Vendor)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch SwitchType
                OEM_SwitchType = parse_SwitchType(temp_list)
                API_SwitchType = API_info.get("SwitchType")
                if OEM_SwitchType != API_SwitchType:
                    is_fail = True
                    fail_text = "[OEM] {0} SwitchType: {1}\n[API] {0} SwitchType: {2}".format(switch,OEM_SwitchType,API_SwitchType)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Temperature
                OEM_Temperature = parse_Temperature(temp_list)
                API_Temperature = API_info.get("Temperature")
                if OEM_Temperature != API_Temperature:
                    is_fail = True
                    fail_text = "[OEM] {0} Temperature: {1}\n[API] {0} Temperature: {2}".format(switch,OEM_Temperature,API_Temperature)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Pwr_consump
                OEM_Pwr_consump = parse_Pwr_consump(temp_list)
                API_Pwr_consump = API_info.get("Pwr_consump")
                if OEM_Pwr_consump != API_Pwr_consump:
                    is_fail = True
                    fail_text = "[OEM] {0} Pwr_consump: {1}\n[API] {0} Pwr_consump: {2}".format(switch,OEM_Pwr_consump,API_Pwr_consump)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch IP
                OEM_IP = parse_IP(temp_list)
                API_IP = API_info.get("IP")
                if OEM_IP != API_IP:
                    is_fail = True
                    fail_text = "[OEM] {0} IP: {1}\n[API] {0} IP: {2}".format(switch,OEM_IP,API_IP)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Netmask
                OEM_Netmask = parse_Netmask(temp_list)
                API_Netmask = API_info.get("Netmask")
                if OEM_Netmask != API_Netmask:
                    is_fail = True
                    fail_text = "[OEM] {0} Netmask: {1}\n[API] {0} Netmask: {2}".format(switch,OEM_Netmask,API_Netmask)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                # Check Switch Gateway
                OEM_Gateway = parse_Gateway(temp_list)
                API_Gateway = API_info.get("Gateway")
                if OEM_Gateway != API_Gateway:
                    is_fail = True
                    fail_text = "[OEM] {0} Gateway: {1}\n[API] {0} Gateway: {2}".format(switch,OEM_Gateway,API_Gateway)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
            else:
                CASE_PASS = False
            if is_fail or not CASE_PASS:
                CASE_PASS = False
                temp_text = "[{0}] Check switch info FAIL !".format(switch)
                MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check switch info".format(switch),flag="FAIL")
            else:
                temp_text = "[{0}] Check switch info PASS.".format(switch)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check switch info".format(switch), flag="PASS")

    # TODO: Set switch via OEM command
    # def d_set_switch_via_OEM(self):
    #     global CASE_PASS
    #     temp_text = "Set switch via OEM command"
    #     CMM.show_message(format_item(temp_text), color="green", timestamp=False)
    #     CMM.save_data(main_log, temp_text, timestamp=False)

    # TODO: Set switch via Web API
    # def f_set_switch_via_API(self):
    #     global CASE_PASS
    #     temp_text = "Set switch via Web API"
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
            show_step_result("[curl] Logout Web", flag="PASS")
        else:
            message = "[curl] Logout Web FAIL !\n{0}".format(output)
            CMM.save_data(main_log, message)
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