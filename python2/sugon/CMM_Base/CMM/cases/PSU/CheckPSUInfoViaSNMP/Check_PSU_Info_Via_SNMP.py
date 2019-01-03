# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import re
import json
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
PSU_NUM = config.PSU_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_PSU_OEM = "raw 0x3a 0x51"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
Present_psu = []
IPMI_PSU_INFO = []
IPMI_PSU_FAIL = False
ITEM_NUM = 0
SET_USER_SNMP = False

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

def getPSUInfoViaSNMP(version,timeout=10):
    global ITEM_NUM
    if version == "3":
        comstr = "-u sugon -a SHA -A 11111111 -l authPriv -x DES -X 11111111"
    else:
        comstr = "-c rwcommstr"
    # psuCount
    psuCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.1".format(version, comstr, timeout, IP)
    # onlineCount
    onlineCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.2".format(version, comstr, timeout, IP)
    # psuIndex
    psuIndexCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.1".format(version, comstr, timeout, IP)
    # pwrState
    pwrStateCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.2".format(version, comstr, timeout, IP)
    # statusWord
    statusWordCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.3".format(version, comstr, timeout, IP)
    # pout
    poutCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.4".format(version, comstr, timeout, IP)
    # pin
    pinCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.5".format(version, comstr, timeout, IP)
    # vout
    voutCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.6".format(version, comstr, timeout, IP)
    # vin
    vinCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.7".format(version, comstr, timeout, IP)
    # iout
    ioutCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.8".format(version, comstr, timeout, IP)
    # iin
    iinCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.9".format(version, comstr, timeout, IP)
    # temperature1
    temperature1Cmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.10".format(version, comstr, timeout, IP)
    # temperature2
    temperature2Cmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.16".format(version, comstr,timeout, IP)
    # fanSpeed
    fanSpeedCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.11".format(version, comstr, timeout, IP)
    # fanDuty
    fanDutyCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.12".format(version, comstr, timeout, IP)
    # vendor
    vendorCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.13".format(version, comstr, timeout, IP)
    # psuModel
    psuModelCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.14".format(version, comstr, timeout, IP)
    # psuSN
    psuSNCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.3.3.1.15".format(version, comstr, timeout, IP)

    cmdDict = collections.OrderedDict()
    cmdDict["psuCount"] = psuCountCmd
    cmdDict["onlineCount"] = onlineCountCmd
    cmdDict["psuIndex"] = psuIndexCmd
    cmdDict["pwrState"] = pwrStateCmd
    cmdDict["statusWord"] = statusWordCmd
    cmdDict["pout"] = poutCmd
    cmdDict["pin"] = pinCmd
    cmdDict["vout"] = voutCmd
    cmdDict["vin"] = vinCmd
    cmdDict["iout"] = ioutCmd
    cmdDict["iin"] = iinCmd
    cmdDict["temperature1"] = temperature1Cmd
    cmdDict["temperature2"] = temperature2Cmd
    cmdDict["fanSpeed"] = fanSpeedCmd
    cmdDict["fanDuty"] = fanDutyCmd
    cmdDict["vendor"] = vendorCmd
    cmdDict["psuModel"] = psuModelCmd
    cmdDict["psuSN"] = psuSNCmd
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
                    if name == "psuCount" or name == "onlineCount":
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
                    temp_list[7],temp_list[8],temp_list[9],temp_list[10],temp_list[11],
                    temp_list[12],temp_list[13],temp_list[14],temp_list[15],temp_list[16],temp_list[17]):
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

def parse_statusWord(tempList):
    value = CMM.convert_to_decimal_multi(tempList[2:4])
    if str(value) == "0" or value > 0:
        return value
    return "Unknown"






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

    def c_get_psu_via_ipmi(self):
        global Present_psu
        global IPMI_PSU_INFO
        global IPMI_PSU_FAIL
        global CASE_PASS
        temp_text = "- Get PSU info via IPMI -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for psu_id in range(1,int(PSU_NUM)+1):
            psu = "PSU{0}".format(psu_id)
            is_fail = False
            OEM_psuIndex, OEM_pwrState, OEM_statusWord, OEM_pout, OEM_pin, OEM_vout, OEM_vin, OEM_iout, OEM_iin, \
            OEM_temperature1, OEM_temperature2, OEM_fanSpeed, OEM_fanDuty, OEM_vendor, OEM_psuModel, \
            OEM_psuSN = ["Unknown"] * 16
            OEM_info = GetPSUInfoViaOEM(psu_id)
            if OEM_info:
                temp_list = OEM_info.split()
                OEM_Present = parse_Present(temp_list)
                if OEM_Present[1] == 1:
                    Present_psu.append(psu_id)
                    OEM_isPSUOn = parse_isPSUOn(temp_list)
                    if OEM_isPSUOn == "ON":
                        OEM_pwrState = 2
                    elif OEM_isPSUOn == "OFF":
                        OEM_pwrState = 1
                else:
                    OEM_pwrState = 0
                OEM_statusWord = parse_statusWord(temp_list)
                OEM_psuIndex = parse_id(temp_list)
                OEM_pout = parse_Pout(temp_list)
                OEM_pin = parse_Pin(temp_list)
                OEM_vout = parse_Vout(temp_list)
                OEM_vin = parse_Vin(temp_list)
                OEM_iout = parse_Iout(temp_list)
                OEM_iin = parse_Iin(temp_list)
                temp = parse_Temp(temp_list)
                OEM_temperature1 = temp[0] if isinstance(temp,tuple) else temp
                OEM_temperature2 = temp[1] if isinstance(temp,tuple) else temp
                OEM_fanSpeed = parse_Fan1Speed(temp_list)
                OEM_fanDuty = parse_FanDuty(temp_list)
                OEM_vendor = parse_Vendor(temp_list)
                OEM_psuModel = parse_Model(temp_list)
                OEM_psuSN = parse_SN(temp_list)
            else:
                is_fail = True
                IPMI_PSU_FAIL = True
            IPMI_PSU_INFO.append([OEM_psuIndex, OEM_pwrState, OEM_statusWord, OEM_pout, OEM_pin, OEM_vout, OEM_vin, OEM_iout, OEM_iin,OEM_temperature1, OEM_temperature2, OEM_fanSpeed, OEM_fanDuty, OEM_vendor,OEM_psuModel, OEM_psuSN])
            temp_text = "[{0}] IPMI info".format(psu)
            if is_fail:
                CASE_PASS = False
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
                MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            else:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
        CMM.save_data(main_log, "IPMI PSU info list\n{0}".format(IPMI_PSU_INFO), timestamp=False)

    def d_check_psu_via_snmpv1(self,version="1"):
        if IPMI_PSU_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check PSU info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getPSUInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        psu_info = temp_list[2:]
        temp_text = "Check PSU total number"
        if total_num == PSU_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "PSU total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check PSU present number"
        if present_num == len(Present_psu):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "PSU present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for psu_id in range(1, int(PSU_NUM) + 1):
            psu = "PSU{0}".format(psu_id)
            is_fail = False
            index = psu_id - 1
            temp_snmp = psu_info[index]
            temp_ipmi = map(str,IPMI_PSU_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(psu,show_version)
            compare_flag = False
            try:
                if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                    # if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-3:] == temp_ipmi[-3:]:
                        """ 两者差值小于IPMI值 即为PASS """
                        temp_pout = float(temp_snmp[2]) - float(temp_ipmi[2])
                        temp_pin = float(temp_snmp[3]) - float(temp_ipmi[3])
                        temp_vout = float(temp_snmp[4]) - float(temp_ipmi[4])
                        temp_vin = float(temp_snmp[5]) - float(temp_ipmi[5])
                        temp_iout = float(temp_snmp[6]) - float(temp_ipmi[6])
                        temp_iin = float(temp_snmp[7]) - float(temp_ipmi[7])
                        temp_temperature = float(temp_snmp[8]) - float(temp_ipmi[8])
                        temp_fanSpeed = float(temp_snmp[9]) - float(temp_ipmi[9])
                        if abs(temp_pout) <= float(temp_ipmi[2]) and \
                            abs(temp_pin) <= float(temp_ipmi[3]) and \
                            abs(temp_vout) <= float(temp_ipmi[4]) and \
                            abs(temp_vin) <= float(temp_ipmi[5]) and \
                            abs(temp_iout) <= float(temp_ipmi[6]) and \
                            abs(temp_iin) <= float(temp_ipmi[7]) and \
                            abs(temp_temperature) <= float(temp_ipmi[8]) and \
                            abs(temp_fanSpeed) <= float(temp_ipmi[9]):
                            if int(temp_snmp[2]) > 0:
                                compare_flag = True
                            elif int(temp_snmp[2]) == 0 and temp_snmp[1] == temp_ipmi[1]:
                                compare_flag = True
            except: pass
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

    def e_check_psu_via_snmpv2(self,version="2c"):
        if IPMI_PSU_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check PSU info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getPSUInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        psu_info = temp_list[2:]
        temp_text = "Check PSU total number"
        if total_num == PSU_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "PSU total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check PSU present number"
        if present_num == len(Present_psu):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "PSU present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for psu_id in range(1, int(PSU_NUM) + 1):
            psu = "PSU{0}".format(psu_id)
            is_fail = False
            index = psu_id - 1
            temp_snmp = psu_info[index]
            temp_ipmi = map(str,IPMI_PSU_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(psu,show_version)
            compare_flag = False
            try:
                if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                    # if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-3:] == temp_ipmi[-3:]:
                        """ 两者差值小于IPMI值 即为PASS """
                        temp_pout = float(temp_snmp[2]) - float(temp_ipmi[2])
                        temp_pin = float(temp_snmp[3]) - float(temp_ipmi[3])
                        temp_vout = float(temp_snmp[4]) - float(temp_ipmi[4])
                        temp_vin = float(temp_snmp[5]) - float(temp_ipmi[5])
                        temp_iout = float(temp_snmp[6]) - float(temp_ipmi[6])
                        temp_iin = float(temp_snmp[7]) - float(temp_ipmi[7])
                        temp_temperature = float(temp_snmp[8]) - float(temp_ipmi[8])
                        temp_fanSpeed = float(temp_snmp[9]) - float(temp_ipmi[9])
                        if abs(temp_pout) <= float(temp_ipmi[2]) and \
                            abs(temp_pin) <= float(temp_ipmi[3]) and \
                            abs(temp_vout) <= float(temp_ipmi[4]) and \
                            abs(temp_vin) <= float(temp_ipmi[5]) and \
                            abs(temp_iout) <= float(temp_ipmi[6]) and \
                            abs(temp_iin) <= float(temp_ipmi[7]) and \
                            abs(temp_temperature) <= float(temp_ipmi[8]) and \
                            abs(temp_fanSpeed) <= float(temp_ipmi[9]):
                            if int(temp_snmp[2]) > 0:
                                compare_flag = True
                            elif int(temp_snmp[2]) == 0 and temp_snmp[1] == temp_ipmi[1]:
                                compare_flag = True
            except: pass
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
        if IPMI_PSU_FAIL:
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

    def g_check_psu_via_snmpv3(self,version="3"):
        if IPMI_PSU_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check PSU info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getPSUInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        psu_info = temp_list[2:]
        temp_text = "Check PSU total number"
        if total_num == PSU_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "PSU total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check PSU present number"
        if present_num == len(Present_psu):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "PSU present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for psu_id in range(1, int(PSU_NUM) + 1):
            psu = "PSU{0}".format(psu_id)
            is_fail = False
            index = psu_id - 1
            temp_snmp = psu_info[index]
            temp_ipmi = map(str,IPMI_PSU_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(psu,show_version)
            compare_flag = False
            try:
                if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                    # if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    if temp_snmp[0] == temp_ipmi[0] and temp_snmp[2] == temp_ipmi[2] and temp_snmp[-3:] == temp_ipmi[-3:]:
                        """ 两者差值小于IPMI值 即为PASS """
                        temp_pout = float(temp_snmp[2]) - float(temp_ipmi[2])
                        temp_pin = float(temp_snmp[3]) - float(temp_ipmi[3])
                        temp_vout = float(temp_snmp[4]) - float(temp_ipmi[4])
                        temp_vin = float(temp_snmp[5]) - float(temp_ipmi[5])
                        temp_iout = float(temp_snmp[6]) - float(temp_ipmi[6])
                        temp_iin = float(temp_snmp[7]) - float(temp_ipmi[7])
                        temp_temperature = float(temp_snmp[8]) - float(temp_ipmi[8])
                        temp_fanSpeed = float(temp_snmp[9]) - float(temp_ipmi[9])
                        if abs(temp_pout) <= float(temp_ipmi[2]) and \
                            abs(temp_pin) <= float(temp_ipmi[3]) and \
                            abs(temp_vout) <= float(temp_ipmi[4]) and \
                            abs(temp_vin) <= float(temp_ipmi[5]) and \
                            abs(temp_iout) <= float(temp_ipmi[6]) and \
                            abs(temp_iin) <= float(temp_ipmi[7]) and \
                            abs(temp_temperature) <= float(temp_ipmi[8]) and \
                            abs(temp_fanSpeed) <= float(temp_ipmi[9]):
                            if int(temp_snmp[2]) > 0:
                                compare_flag = True
                            elif int(temp_snmp[2]) == 0 and temp_snmp[1] == temp_ipmi[1]:
                                compare_flag = True
            except: pass
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