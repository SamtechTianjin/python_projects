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
SWITCH_NUM = config.SWITCH_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_SWITCH_API = "/api/cmminfo/switches/"
GET_SWITCH_OEM = "raw 0x3a 0x5f"
SET_SWITCH_OEM = "raw 0x3a 0x5e"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
API接口返回值:
id,swPresent,Present,Status,Vendor,SwitchType,Temperature,Pwr_consump,IP,Netmask,Gateway
"""

# 获得指定id的Switch信息--OEM  id从1开始
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

# 获得指定id的Switch信息--API  id从1开始
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

def set_switch_ipv4_API(switch_id,ip,netmask,gateway):
    restapi = "/api/cmminfo/Setswitchipv4"
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmdtype':3,'address':'%s','netmask':'%s','gateway':'%s'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,switch_id,ip,netmask,gateway,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Set switch{0} ipv4\n{1}\nreturncode: {2}\n{3}".format(switch_id,cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    set_value = {}
    if status == 0:
        try:
            temp = json.loads(output)
        except Exception as e:
            message = "[Switch{0}] {1}".format(switch_id,e)
            CMM.save_data(main_log,message,timestamp=False)
            CMM.show_message(message,timestamp=False,color="red")
        else:
            if temp.get("error"):
                CMM.show_message("{0}".format(temp),timestamp=False,color="red")
            else:
                set_value["IP"] = ip
                set_value["Netmask"] = netmask
                set_value["Gateway"] = gateway
    return set_value

def set_switch_ipv4_OEM(switch_id,ip,netmask,gateway):
    OEM_id = switch_id - 1
    temp_list = []
    for i in [ip,netmask,gateway]:
        mid_list = []
        for item in i.split("."):
            mid_list.append(hex(int(item)))
        temp = " ".join(mid_list)
        temp_list.append(temp)
    cmd = "{0} {1} {2} 0x03 {3} {4} {5}".format(IPMITOOL,SET_SWITCH_OEM,hex(OEM_id),temp_list[0],temp_list[1],temp_list[2])
    status, output = CMM.retry_run_cmd(cmd)
    message = "[OEM] Set switch{0} ipv4\n{1}\nreturncode: {2}\n{3}".format(switch_id, cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status != 0:
        message = "[Switch{0}] {1}".format(switch_id, output)
        CMM.save_data(main_log, message, timestamp=False)
        CMM.show_message(message, timestamp=False, color="red")
        return False
    return True

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
        global LOGIN_FAIL
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
            LOGIN_FAIL = True

    def c_check_switch_info(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check switch info -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        # MAIN_LOG_list.append(temp_text)
        id_list,Present_list,Status_list,Vendor_list,SwitchType_list,Temperature_list,Pwr_consump_list,IP_list,Netmask_list,Gateway_list = [],[],[],[],[],[],[],[],[],[]
        for id in range(1,int(SWITCH_NUM)+1):
            switch = "Switch{0}".format(id)
            is_fail = False
            OEM_info = GetSwitchInfoViaOEM(id)
            API_info = GetSwitchInfoViaAPI(CSRFToken,id)
            if OEM_info and API_info:
                temp_list = OEM_info.split()
                # Check Switch id
                message = "- Check Switch id -"
                if message not in id_list:
                    id_list.append(message)
                OEM_id = parse_id(temp_list)
                API_id = API_info.get("id")
                if OEM_id != API_id:
                    is_fail = True
                    fail_text = "[OEM] {0} id: {1}\n[API] {0} id: {2}".format(switch,OEM_id,API_id)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    id_list.append("[OEM] {0} id: {1}".format(switch,OEM_id))
                    id_list.append("[API] {0} id: {1}".format(switch,API_id))
                # Check Switch Present
                message = "- Check Switch Present -"
                if message not in Present_list:
                    Present_list.append(message)
                OEM_Present_0,OEM_Present_1 = parse_Present(temp_list)
                API_Present_0 = API_info.get("Present")
                # # 兼容Present前面多出空格 更改后注释掉
                # if API_Present_0 == None:
                #     API_Present_0 = API_info.get(" Present")
                API_Present_1 = API_info.get("swPresent")
                if OEM_Present_0 != API_Present_0 or OEM_Present_1 != API_Present_1:
                    is_fail = True
                    fail_text = "[OEM] {0} Present: {1}, swPresent: {2}\n[API] {0} Present: {3}, swPresent: {4}".format\
                        (switch,OEM_Present_0,OEM_Present_1,API_Present_0,API_Present_1)
                    CMM.save_data(main_log, fail_text, timestamp=False)
                    CMM.show_message(fail_text, timestamp=False)
                    Present_list.append("[OEM] {0} Present: {1}, swPresent: {2}".format(switch,OEM_Present_0,OEM_Present_1))
                    Present_list.append("[API] {0} Present: {1}, swPresent: {2}".format(switch,API_Present_0,API_Present_1))
                # Check Switch Status
                message = "- Check Switch Status -"
                if message not in Status_list:
                    Status_list.append(message)
                OEM_Status = parse_Status(temp_list)
                API_Status = API_info.get("Status")
                if OEM_Status != API_Status:
                    is_fail = True
                    fail_text = "[OEM] {0} Status: {1}\n[API] {0} Status: {2}".format(switch,OEM_Status,API_Status)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Status_list.append("[OEM] {0} Status: {1}".format(switch,OEM_Status))
                    Status_list.append("[API] {0} Status: {1}".format(switch,API_Status))
                # Check Switch Vendor
                message = "- Check Switch Vendor -"
                if message not in Vendor_list:
                    Vendor_list.append(message)
                OEM_Vendor = parse_Vendor(temp_list)
                API_Vendor = API_info.get("Vendor")
                if OEM_Vendor != API_Vendor:
                    is_fail = True
                    fail_text = "[OEM] {0} Vendor: {1}\n[API] {0} Vendor: {2}".format(switch,OEM_Vendor,API_Vendor)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Vendor_list.append("[OEM] {0} Vendor: {1}".format(switch,OEM_Vendor))
                    Vendor_list.append("[API] {0} Vendor: {1}".format(switch,API_Vendor))
                # Check Switch SwitchType
                message = "- Check Switch SwitchType -"
                if message not in SwitchType_list:
                    SwitchType_list.append(message)
                OEM_SwitchType = parse_SwitchType(temp_list)
                API_SwitchType = API_info.get("SwitchType")
                if OEM_SwitchType != API_SwitchType:
                    is_fail = True
                    fail_text = "[OEM] {0} SwitchType: {1}\n[API] {0} SwitchType: {2}".format(switch,OEM_SwitchType,API_SwitchType)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    SwitchType_list.append("[OEM] {0} SwitchType: {1}".format(switch,OEM_SwitchType))
                    SwitchType_list.append("[API] {0} SwitchType: {1}".format(switch,API_SwitchType))
                # Check Switch Temperature
                message = "- Check Switch Temperature -"
                if message not in Temperature_list:
                    Temperature_list.append(message)
                pass_interval = 10
                OEM_Temperature = parse_Temperature(temp_list)
                API_Temperature = API_info.get("Temperature")
                if isinstance(OEM_Temperature,int) and isinstance(API_Temperature,int) and abs(OEM_Temperature-API_Temperature) < pass_interval:
                    pass
                elif API_Present_1 == 0 and OEM_Temperature == "" and API_Temperature == "":
                    pass
                else:
                    is_fail = True
                    fail_text = "[OEM] {0} Temperature: {1}\n[API] {0} Temperature: {2}".format(switch,OEM_Temperature,API_Temperature)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Temperature_list.append("[OEM] {0} Temperature: {1}".format(switch,OEM_Temperature))
                    Temperature_list.append("[API] {0} Temperature: {1}".format(switch,API_Temperature))
                # Check Switch Pwr_consump
                message = "- Check Switch Pwr_consump -"
                if message not in Pwr_consump_list:
                    Pwr_consump_list.append(message)
                pass_interval = 10
                OEM_Pwr_consump = parse_Pwr_consump(temp_list)
                API_Pwr_consump = API_info.get("Pwr_consump")
                if isinstance(OEM_Pwr_consump, int) and isinstance(API_Pwr_consump, int) and abs(OEM_Pwr_consump-API_Pwr_consump) < pass_interval:
                    pass
                elif API_Present_1 == 0 and OEM_Pwr_consump == "" and API_Pwr_consump == "":
                    pass
                else:
                    is_fail = True
                    fail_text = "[OEM] {0} Pwr_consump: {1}\n[API] {0} Pwr_consump: {2}".format(switch,OEM_Pwr_consump,API_Pwr_consump)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Pwr_consump_list.append("[OEM] {0} Pwr_consump: {1}".format(switch,OEM_Pwr_consump))
                    Pwr_consump_list.append("[API] {0} Pwr_consump: {1}".format(switch,API_Pwr_consump))
                # Check Switch IP
                message = "- Check Switch IP -"
                if message not in IP_list:
                    IP_list.append(message)
                OEM_IP = parse_IP(temp_list)
                API_IP = API_info.get("IP")
                if OEM_IP != API_IP:
                    is_fail = True
                    fail_text = "[OEM] {0} IP: {1}\n[API] {0} IP: {2}".format(switch,OEM_IP,API_IP)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    IP_list.append("[OEM] {0} IP: {1}".format(switch,OEM_IP))
                    IP_list.append("[API] {0} IP: {1}".format(switch,API_IP))
                # Check Switch Netmask
                message = "- Check Switch Netmask -"
                if message not in Netmask_list:
                    Netmask_list.append(message)
                OEM_Netmask = parse_Netmask(temp_list)
                API_Netmask = API_info.get("Netmask")
                if OEM_Netmask != API_Netmask:
                    is_fail = True
                    fail_text = "[OEM] {0} Netmask: {1}\n[API] {0} Netmask: {2}".format(switch,OEM_Netmask,API_Netmask)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Netmask_list.append("[OEM] {0} Netmask: {1}".format(switch,OEM_Netmask))
                    Netmask_list.append("[API] {0} Netmask: {1}".format(switch,API_Netmask))
                # Check Switch Gateway
                message = "- Check Switch Gateway -"
                if message not in Gateway_list:
                    Gateway_list.append(message)
                OEM_Gateway = parse_Gateway(temp_list)
                API_Gateway = API_info.get("Gateway")
                if OEM_Gateway != API_Gateway:
                    is_fail = True
                    fail_text = "[OEM] {0} Gateway: {1}\n[API] {0} Gateway: {2}".format(switch,OEM_Gateway,API_Gateway)
                    CMM.save_data(main_log,fail_text,timestamp=False)
                    CMM.show_message(fail_text,timestamp=False)
                    Gateway_list.append("[OEM] {0} Gateway: {1}".format(switch,OEM_Gateway))
                    Gateway_list.append("[API] {0} Gateway: {1}".format(switch,API_Gateway))
            else:
                is_fail = True
            if is_fail:
                CASE_PASS = False
                # temp_text = "[{0}] Check switch info FAIL !".format(switch)
                # MAIN_LOG_list.append(temp_text)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check switch info".format(switch),flag="FAIL")
            else:
                temp_text = "[{0}] Check switch info PASS.".format(switch)
                CMM.save_data(main_log,temp_text,timestamp=False)
                show_step_result("[{0}] Check switch info".format(switch), flag="PASS")
        for l in [id_list,Present_list,Status_list,Vendor_list,SwitchType_list,Temperature_list,Pwr_consump_list,IP_list,Netmask_list,Gateway_list]:
            for item in l:
                MAIN_LOG_list.append(item)

    def d_set_switch_ipv4_via_OEM(self):
        global CASE_PASS
        temp_text = "- Set Switch ipv4 via OEM command -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        random_base = random.randrange(100,200)
        for switch_id in range(1, int(SWITCH_NUM) + 1):
            check_switch = GetSwitchInfoViaAPI(CSRFToken,switch_id)
            if check_switch.get("swPresent") == 0:
                continue
            default_IP = check_switch.get("IP")
            default_Netmask = check_switch.get("Netmask")
            default_Gateway = check_switch.get("Gateway")
            set_IP = "10.0.0.{0}".format(int(switch_id) + random_base)
            set_Netmask = "255.255.255.0"
            set_Gateway = "10.0.0.254"
            status = set_switch_ipv4_OEM(switch_id,set_IP,set_Netmask,set_Gateway)
            if status:
                time.sleep(10)
                API_info = GetSwitchInfoViaAPI(CSRFToken, switch_id)
                get_IP,get_Netmask,get_Gateway = [API_info.get(item) for item in ["IP","Netmask","Gateway"]]
                if set_IP != get_IP or set_Netmask != get_Netmask or set_Gateway != get_Gateway:
                    CASE_PASS = False
                    message = "[OEM] Set switch{0} ipv4 FAIL !".format(switch_id)
                    MAIN_LOG_list.append(message)
                    message = "{0}\n{1}\n{2}".format(message,"Set value: {0} {1} {2}".format(set_IP,set_Netmask,set_Gateway),"Get value: {0} {1} {2}".format(get_IP,get_Netmask,get_Gateway))
                    CMM.show_message(message, timestamp=False, color="red")
                    CMM.save_data(main_log, message, timestamp=False)
                else:
                    show_step_result("[OEM] Set switch{0} ipv4".format(switch_id),flag="PASS")
                    status = set_switch_ipv4_OEM(switch_id,default_IP,default_Netmask,default_Gateway)
                    if status:
                        time.sleep(10)
                        API_info = GetSwitchInfoViaAPI(CSRFToken, switch_id)
                        get_IP, get_Netmask, get_Gateway = [API_info.get(item) for item in ["IP", "Netmask", "Gateway"]]
                        temp_text = "[OEM] Restore switch{0} ipv4".format(switch_id)
                        if get_IP == default_IP and get_Netmask == default_Netmask and get_Gateway == default_Gateway:
                            show_step_result(temp_text,flag="PASS")
                            CMM.save_step_result(main_log,temp_text,flag="PASS")
                        else:
                            show_step_result(temp_text,flag="FAIL")
                            CMM.save_step_result(main_log,temp_text,flag="FAIL")

            else:
                CASE_PASS = False
                message = "[OEM] Set switch{0} ipv4 FAIL !".format(switch_id)
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_data(main_log,message,timestamp=False)
                MAIN_LOG_list.append(message)

    def f_set_switch_ipv4_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set Switch ipv4 via Web API -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        random_base = random.randrange(100,200)
        for switch_id in range(1, int(SWITCH_NUM) + 1):
            check_switch = GetSwitchInfoViaAPI(CSRFToken,switch_id)
            if check_switch.get("swPresent") == 0:
                continue
            default_IP = check_switch.get("IP")
            default_Netmask = check_switch.get("Netmask")
            default_Gateway = check_switch.get("Gateway")
            set_IP = "10.0.0.{0}".format(int(switch_id) + random_base)
            set_Netmask = "255.255.255.0"
            set_Gateway = "10.0.0.254"
            set_value = set_switch_ipv4_API(switch_id,set_IP,set_Netmask,set_Gateway)
            if set_value:
                time.sleep(10)
                API_info = GetSwitchInfoViaAPI(CSRFToken, switch_id)
                set_IP,set_Netmask,set_Gateway = [set_value.get(item) for item in ["IP","Netmask","Gateway"]]
                get_IP,get_Netmask,get_Gateway = [API_info.get(item) for item in ["IP","Netmask","Gateway"]]
                if set_IP != get_IP or set_Netmask != get_Netmask or set_Gateway != get_Gateway:
                    CASE_PASS = False
                    message = "[API] Set switch{0} ipv4 FAIL !".format(switch_id)
                    MAIN_LOG_list.append(message)
                    message = "{0}\n{1}\n{2}".format(message,"Set value: {0} {1} {2}".format(set_IP,set_Netmask,set_Gateway),"Get value: {0} {1} {2}".format(get_IP,get_Netmask,get_Gateway))
                    CMM.show_message(message, timestamp=False, color="red")
                    CMM.save_data(main_log, message, timestamp=False)
                else:
                    show_step_result("[API] Set switch{0} ipv4".format(switch_id),flag="PASS")
                    set_value = set_switch_ipv4_API(switch_id,default_IP,default_Netmask,default_Gateway)
                    if set_value:
                        time.sleep(10)
                        API_info = GetSwitchInfoViaAPI(CSRFToken, switch_id)
                        set_IP, set_Netmask, set_Gateway = [set_value.get(item) for item in["IP", "Netmask", "Gateway"]]
                        get_IP, get_Netmask, get_Gateway = [API_info.get(item) for item in ["IP", "Netmask", "Gateway"]]
                        temp_text = "[API] Restore switch{0} ipv4".format(switch_id)
                        if set_IP == get_IP and set_Netmask == get_Netmask and set_Gateway == get_Gateway:
                            show_step_result(temp_text,flag="PASS")
                            CMM.save_step_result(main_log,temp_text,flag="PASS")
                        else:
                            show_step_result(temp_text,flag="FAIL")
                            CMM.save_step_result(main_log,temp_text,flag="FAIL")
            else:
                CASE_PASS = False
                message = "[API] Set switch{0} ipv4 FAIL !".format(switch_id)
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_data(main_log,message,timestamp=False)
                MAIN_LOG_list.append(message)

    def g_curl_logout(self):
        if LOGIN_FAIL:
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