# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import json
import re
import collections
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
GET_SWITCH_OEM = "raw 0x3a 0x5f"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

Present_switch = []
IPMI_SWITCH_INFO = []
IPMI_SWITCH_FAIL = False
ITEM_NUM = 0
SET_USER_SNMP = False

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

def getSwitchInfoViaSNMP(version,timeout=10):
    global ITEM_NUM
    if version == "3":
        comstr = "-u sugon -a SHA -A 11111111 -l authPriv -x DES -X 11111111"
    else:
        comstr = "-c rwcommstr"
    # switchCount
    switchCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.1".format(version, comstr, timeout, IP)
    # onlineCount
    onlineCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.2".format(version, comstr, timeout, IP)
    # switchIndex
    switchIndexCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.1".format(version, comstr, timeout, IP)
    # switchState
    switchStateCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.2".format(version, comstr, timeout, IP)
    # switchType
    switchTypeCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.3".format(version, comstr, timeout, IP)
    # temperature
    temperatureCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.4".format(version, comstr, timeout, IP)
    # pwrConsump
    pwrConsumpCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.5".format(version, comstr, timeout, IP)
    # ip
    ipCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.6".format(version, comstr, timeout, IP)
    # netmask
    netmaskCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.7".format(version, comstr, timeout, IP)
    # gateway
    gatewayCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.8".format(version, comstr, timeout, IP)
    # vendor
    vendorCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.5.3.1.9".format(version, comstr, timeout, IP)
    cmdDict = collections.OrderedDict()
    cmdDict["switchCount"] = switchCountCmd
    cmdDict["onlineCount"] = onlineCountCmd
    cmdDict["switchIndex"] = switchIndexCmd
    cmdDict["switchState"] = switchStateCmd
    cmdDict["switchType"] = switchTypeCmd
    cmdDict["temperature"] = temperatureCmd
    cmdDict["pwrConsump"] = pwrConsumpCmd
    cmdDict["ip"] = ipCmd
    cmdDict["netmask"] = netmaskCmd
    cmdDict["gateway"] = gatewayCmd
    cmdDict["vendor"] = vendorCmd
    ITEM_NUM = len(cmdDict.keys())-2
    result_list = []
    temp_list = []
    for name,cmd in cmdDict.iteritems():
        temp_data = []
        status,output = CMM.retry_run_cmd(cmd)
        message = "\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
        CMM.save_data(main_log,message,timestamp=False)
        if status == 0:
            for line in output.splitlines():
                m = re.match(r'SNMP.*enterprises.*',line)
                if m:
                    """ vendor/model/SN 格式异常 需要对冒号数量进行判断 """
                    if m.group().count(":") == 2:
                        value = m.group().split()[-1].strip(" \"\'")
                    else:
                        value = m.group().split(":")[-1].strip(" \"\'")
                    if name == "switchCount" or name == "onlineCount":
                        try:
                            temp_data = int(value)
                        except:
                            temp_data = "Unknown"
                        break
                    else:
                        temp_data.append(value)
        else:
            temp_text = "[SNMP] Get {0} info".format(name)
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        temp_list.append(temp_data)
    result_list.extend(temp_list[:2])
    for item in zip(temp_list[2],temp_list[3],temp_list[4],temp_list[5],temp_list[6],
                    temp_list[7],temp_list[8],temp_list[9],temp_list[10]):
        result_list.append(list(item))
    return result_list

def setUserSNMP():
    is_fail = False
    restapi = "/api/settings/users/3"
    cmd1 = "curl -X PUT -H \"X-CSRFTOKEN:%s\" -H \"Content-Type: application/json\" -d \"{'id':3,'name':'sugon','access':1,'kvm':1,'vmedia':1,'snmp':1,'prev_snmp':1,'network_privilege':'administrator','fixed_user_count':1,'snmp_access':'read_write','OEMProprietary_level_Privilege':1,'privilege_limit_serial':'none','snmp_authentication_protocol':'sha','snmp_privacy_protocol':'des','email_id':'sugon_sit@163.com','email_format':'ami_format','ssh_key':'Not Available','creation_time':1513303037,'priv_changed':0,'turnon_password_expiry':0,'expiry_date':'','belong_group':4,'group_name':'Unclassified','changepassword':1,'UserOperation':1,'password':'11111111','confirm_password':'11111111','password_size':'bytes_16'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    restapi = "/api/settings/setpasswordexpiry"
    cmd2 = "curl -X PUT -H \"X-CSRFTOKEN:%s\" -H \"Content-Type: application/json\" -d \"{'userId':3,'userName':'sugon','expiry':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    restapi = "/api/settings/update_user_belong_group"
    cmd3 = "curl -X PUT -H \"X-CSRFTOKEN:%s\" -H \"Content-Type: application/json\" -d \"{'userId':3,'groupId':4,'type':1}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    for cmd in [cmd1,cmd2,cmd3]:
        status,output = CMM.retry_run_cmd(cmd)
        if status == 0:
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
                    MAIN_LOG_list.append("{0}".format(output))
                    CMM.show_message("{0}".format(output),timestamp=False,color="red")
        else:
            is_fail = True
        if is_fail:
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
    except:
        Temperature = "Unknown"
    return Temperature

def parse_Pwr_consump(temp_list):
    try:
        Pwr_consump = int(temp_list[21],16)
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

    def c_get_switch_via_ipmi(self):
        global Present_switch
        global IPMI_SWITCH_INFO
        global IPMI_SWITCH_FAIL
        global CASE_PASS
        temp_text = "- Get Switch info via IPMI -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for switch_id in range(1,int(SWITCH_NUM)+1):
            switch = "Switch{0}".format(switch_id)
            is_fail = False
            OEM_switchIndex, OEM_switchState, OEM_switchType, OEM_temperature, OEM_pwrConsump, \
            OEM_ip, OEM_netmask, OEM_gateway, OEM_vendor = ["Unknown"] * 9
            OEM_info = GetSwitchInfoViaOEM(switch_id)
            if OEM_info:
                temp_list = OEM_info.split()
                OEM_Present = parse_Present(temp_list)
                if OEM_Present[1] == 1:
                    Present_switch.append(switch_id)
                    OEM_Power = parse_Status(temp_list)
                    if OEM_Power == "Power On":
                        OEM_switchState = 2
                    elif OEM_Power == "Power Off":
                        OEM_switchState = 1
                    elif OEM_Power == "Communication Lost":
                        OEM_switchState = 7
                    elif OEM_Power == "Over Temp":
                        OEM_switchState = 3
                else:
                    OEM_switchState = 0
                OEM_switchIndex = parse_id(temp_list)
                temp = temp_list[19]
                OEM_switchType = int(temp,16)
                OEM_temperature = parse_Temperature(temp_list)
                OEM_pwrConsump = parse_Pwr_consump(temp_list)
                OEM_ip = parse_IP(temp_list)
                OEM_netmask = parse_Netmask(temp_list)
                OEM_gateway = parse_Gateway(temp_list)
                OEM_vendor = parse_Vendor(temp_list)
            else:
                is_fail = True
                IPMI_SWITCH_FAIL = True
            IPMI_SWITCH_INFO.append([OEM_switchIndex, OEM_switchState, OEM_switchType, OEM_temperature, OEM_pwrConsump,
                                     OEM_ip, OEM_netmask, OEM_gateway, OEM_vendor])
            temp_text = "[{0}] IPMI info".format(switch)
            if is_fail:
                CASE_PASS = False
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
                MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            else:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
        CMM.save_data(main_log, "IPMI Switch info list\n{0}".format(IPMI_SWITCH_INFO), timestamp=False)

    def d_check_switch_via_snmpv1(self,version="1"):
        if IPMI_SWITCH_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Switch info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getSwitchInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        switch_info = temp_list[2:]
        temp_text = "Check Switch total number"
        if total_num == SWITCH_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Switch total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Switch present number"
        if present_num == len(Present_switch):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Switch present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for switch_id in range(1, int(SWITCH_NUM) + 1):
            switch = "Switch{0}".format(switch_id)
            is_fail = False
            index = switch_id - 1
            temp_snmp = switch_info[index]
            temp_ipmi = map(str,IPMI_SWITCH_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(switch,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:3] == temp_ipmi[:3] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    """ 两者差值小于IPMI值 即为PASS """
                    temp_temperature = float(temp_snmp[3]) - float(temp_ipmi[3])
                    temp_pwrConsump = float(temp_snmp[4]) - float(temp_ipmi[4])
                    if abs(temp_temperature) <= float(temp_ipmi[3])/2 and \
                        abs(temp_pwrConsump) <= float(temp_ipmi[4])/2:
                        compare_flag = True
            if compare_flag:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
            else:
                is_fail = True
                message = "[IPMI] {0}".format(temp_ipmi)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                message = "[SNMP] {0}".format(temp_snmp)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
            if is_fail:
                CASE_PASS = False

    def e_check_switch_via_snmpv2(self,version="2c"):
        if IPMI_SWITCH_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Switch info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getSwitchInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        switch_info = temp_list[2:]
        temp_text = "Check Switch total number"
        if total_num == SWITCH_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Switch total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Switch present number"
        if present_num == len(Present_switch):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Switch present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for switch_id in range(1, int(SWITCH_NUM) + 1):
            switch = "Switch{0}".format(switch_id)
            is_fail = False
            index = switch_id - 1
            temp_snmp = switch_info[index]
            temp_ipmi = map(str,IPMI_SWITCH_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(switch,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:3] == temp_ipmi[:3] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    """ 两者差值小于IPMI值 即为PASS """
                    temp_temperature = float(temp_snmp[3]) - float(temp_ipmi[3])
                    temp_pwrConsump = float(temp_snmp[4]) - float(temp_ipmi[4])
                    if abs(temp_temperature) <= float(temp_ipmi[3])/2 and \
                        abs(temp_pwrConsump) <= float(temp_ipmi[4])/2:
                        compare_flag = True
            if compare_flag:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
            else:
                is_fail = True
                message = "[IPMI] {0}".format(temp_ipmi)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                message = "[SNMP] {0}".format(temp_snmp)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
            if is_fail:
                CASE_PASS = False

    def f_set_user_snmp(self):
        if IPMI_SWITCH_FAIL:
            return False
        global CASE_PASS
        global SET_USER_SNMP
        temp_text = "- Set user for SNMP V3 -"
        CMM.show_message(format_item(temp_text),timestamp=False,color="green")
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        status = setUserSNMP()
        message = temp_text.strip(" -")
        if status:
            SET_USER_SNMP = True
            CMM.save_step_result(main_log,message,"PASS")
            show_step_result(message,"PASS")
            time.sleep(20)
        else:
            CASE_PASS = False
            CMM.save_step_result(main_log,message,"FAIL")
            show_step_result(message,"FAIL")

    def g_check_switch_via_snmpv3(self,version="3"):
        if IPMI_SWITCH_FAIL:
            return False
        elif not SET_USER_SNMP:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Switch info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getSwitchInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        switch_info = temp_list[2:]
        temp_text = "Check Switch total number"
        if total_num == SWITCH_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Switch total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Switch present number"
        if present_num == len(Present_switch):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Switch present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for switch_id in range(1, int(SWITCH_NUM) + 1):
            switch = "Switch{0}".format(switch_id)
            is_fail = False
            index = switch_id - 1
            temp_snmp = switch_info[index]
            temp_ipmi = map(str,IPMI_SWITCH_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(switch,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:3] == temp_ipmi[:3] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    """ 两者差值小于IPMI值 即为PASS """
                    temp_temperature = float(temp_snmp[3]) - float(temp_ipmi[3])
                    temp_pwrConsump = float(temp_snmp[4]) - float(temp_ipmi[4])
                    if abs(temp_temperature) <= float(temp_ipmi[3])/2 and \
                        abs(temp_pwrConsump) <= float(temp_ipmi[4])/2:
                        compare_flag = True
            if compare_flag:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
            else:
                is_fail = True
                message = "[IPMI] {0}".format(temp_ipmi)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                message = "[SNMP] {0}".format(temp_snmp)
                MAIN_LOG_list.append(message)
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
            if is_fail:
                CASE_PASS = False

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