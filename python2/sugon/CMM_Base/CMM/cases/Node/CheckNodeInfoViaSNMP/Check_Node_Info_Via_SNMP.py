# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time, datetime
import json
import re
import collections
lis = re.split(r'[/\\]', os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM") + 1])
sys.path.append(path)
from conf.common_config import LOG_DIR, MAIN_LOG
from libs.common import CMM, unicode_convert
from libs.console_show import format_item, show_step_result
import conf.config as config

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR, module_name)
main_log = os.path.join(log_dir, "{0}.log".format(module_name))
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
NODE_NUM = config.NODE_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP, USERNAME, PASSWORD)

LAN_check_dict = collections.OrderedDict()
LAN_check_dict["IPv4Src"] = "4"
LAN_check_dict["IPv4Addr"] = "3"
LAN_check_dict["IPv4SubMask"] = "6"
LAN_check_dict["IPv4DefGateway"] = "12"

Present_Node = []
IPMI_NODE_INFO = []
IPMI_NODE_FAIL = False
ITEM_NUM = 0
SET_USER_SNMP = False

"""
API接口返回值:
PwrState,Present,UID,PwrConsumption
IPv4Src,IPv4Addr,IPv4SubMask,IPv4DefGateway,MACAddr,VlanID,IPv6Enable,IPv6Src,IPv6Addr,IPv6Gateway,NCSIPortNum
BmcVersion,BiosVersion,FruSN
"""



def check_node_Present(node_id):
    OEM_id = node_id
    API_id = node_id + 1
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x03 0x00 0x00".format(IPMITOOL, hex(OEM_id))
    status, output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} Present\n{1}\nreturncode: {2}\n{3}".format(API_id, OEM_cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    OEM_Present = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_Present = temp_list[1]
    return OEM_Present

def check_node_PwrState(node_id):
    OEM_id = node_id
    API_id = node_id + 1
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x01 0x00 0x00".format(IPMITOOL, hex(OEM_id))
    status, output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} PwrState\n{1}\nreturncode: {2}\n{3}".format(API_id, OEM_cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    OEM_PwrState = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_PwrState = temp_list[1]
    return OEM_PwrState

def check_node_PwrConsumption(node_id):
    OEM_id = node_id
    API_id = node_id + 1
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x08 0x00 0x00".format(IPMITOOL, hex(OEM_id))
    status, output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} PwrConsumption\n{1}\nreturncode: {2}\n{3}".format(API_id, OEM_cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    OEM_PwrConsumption = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_PwrConsumption = " ".join(temp_list[1:])
    return OEM_PwrConsumption

def check_node_LAN(node_id):
    OEM_id = node_id
    API_id = node_id + 1
    temp_cmd = "{0} raw 0x3a 0x7c {1} 0x0b".format(IPMITOOL, hex(OEM_id))
    return_list = []
    for item, value in LAN_check_dict.iteritems():
        OEM_cmd = "{0} {1} {2}".format(temp_cmd, hex(1), hex(int(value)))
        status, output = CMM.retry_run_cmd(OEM_cmd)
        message = "OEM Node{0} LAN{1} {2}\n{3}\nreturncode: {4}\n{5}".format(API_id, 1, item,OEM_cmd, status, output)
        CMM.save_data(main_log, message, timestamp=False)
        temp = "Unknown"
        if status == 0:
            temp_list = output.split()
            temp = " ".join(temp_list[1:])
        return_list.append(temp)
    return return_list

def getNodeInfoViaSNMP(version,timeout=10):
    global ITEM_NUM
    if version == "3":
        comstr = "-u sugon -a SHA -A 11111111 -l authPriv -x DES -X 11111111"
    else:
        comstr = "-c rwcommstr"
    # nodeCount
    nodeCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.1".format(version, comstr, timeout, IP)
    # onlineCount
    onlineCountCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.2".format(version, comstr, timeout, IP)
    # nodeIndex
    nodeIndexCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.1".format(version, comstr, timeout, IP)
    # pwrState
    pwrStateCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.2".format(version, comstr, timeout, IP)
    """
    # healthState
    healthStateCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.3".format(version, comstr, timeout, IP)
    """
    # pwrConsumption
    pwrConsumptionCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.4".format(version, comstr, timeout, IP)
    # ipSrc
    ipSrcCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.5".format(version, comstr, timeout, IP)
    # ip
    ipCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.6".format(version, comstr, timeout, IP)
    # netmask
    netmaskCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.7".format(version, comstr, timeout, IP)
    # gateway
    gatewayCmd = "snmpwalk -v {0} {1} -t {2} {3} .1.3.6.1.4.1.27500.1.1.1.2.1.2.3.1.8".format(version, comstr, timeout, IP)
    cmdDict = collections.OrderedDict()
    cmdDict["nodeCount"] = nodeCountCmd
    cmdDict["onlineCount"] = onlineCountCmd
    cmdDict["nodeIndex"] = nodeIndexCmd
    cmdDict["pwrStateCmd"] = pwrStateCmd
    cmdDict["pwrConsumption"] = pwrConsumptionCmd
    cmdDict["ipSrc"] = ipSrcCmd
    cmdDict["ip"] = ipCmd
    cmdDict["netmask"] = netmaskCmd
    cmdDict["gateway"] = gatewayCmd
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
                    if name == "nodeCount" or name == "onlineCount":
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
                    temp_list[7],temp_list[8]):
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




class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log, self.banner(case_name), timestamp=False)

    def b_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        message = "Login Web"
        CMM.show_message(format_item(message), color="green", timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log, message, "PASS")
            CSRFToken = output.strip()
        else:
            LOGIN_FAIL = True
            CASE_PASS = False
            show_step_result(message, "FAIL")
            CMM.save_step_result(main_log, message, "FAIL")
            MAIN_LOG_list.append("{0} FAIL !".format(message))

    def c_get_node_via_ipmi(self):
        global Present_Node
        global IPMI_NODE_FAIL
        global IPMI_NODE_INFO
        global CASE_PASS
        temp_text = "- Get Node info via IPMI -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            node = "Node{0}".format(node_id+1)
            is_fail = False
            OEM_nodeIndex, OEM_pwrState, OEM_pwrConsumption, OEM_ipSrc, OEM_ip, \
            OEM_netmask, OEM_gateway = ["Unknown"] * 7
            try:
                OEM_nodeIndex = node_id+1
                temp = check_node_Present(node_id)
                if temp == "00":
                    OEM_pwrState = 2
                elif temp == "01":
                    Present_Node.append(node_id+1)
                    temp2 = check_node_PwrState(node_id)
                    if temp2 == "01":
                        OEM_pwrState = 1
                    elif temp2 == "00":
                        OEM_pwrState = 0
                temp = check_node_PwrConsumption(node_id)
                OEM_pwrConsumption = CMM.convert_to_decimal_multi(temp.split(), prior="L")
                temp_list = check_node_LAN(node_id)
                temp = temp_list[0]
                if temp == "01":
                    OEM_ipSrc = 1
                elif temp == "02":
                    OEM_ipSrc = 2
                elif temp == "00":
                    OEM_ipSrc = 0
                OEM_ip = CMM.convert_to_IP(temp_list[1].split(),vers=4)
                OEM_netmask = CMM.convert_to_IP(temp_list[2].split(),vers=4)
                OEM_gateway = CMM.convert_to_IP(temp_list[3].split(),vers=4)
            except Exception as e:
                temp_text = "[Exception] {0}".format(e)
                MAIN_LOG_list.append(temp_text)
                CMM.show_message(temp_text,timestamp=False,color="red")
                CMM.save_data(main_log,temp_text,color="red")
                IPMI_NODE_FAIL = True
                is_fail = True
            IPMI_NODE_INFO.append([OEM_nodeIndex, OEM_pwrState, OEM_pwrConsumption, OEM_ipSrc, OEM_ip,
                                   OEM_netmask, OEM_gateway])
            temp_text = "[{0}] IPMI info".format(node)
            if is_fail:
                CASE_PASS = False
                CMM.save_step_result(main_log, temp_text, "FAIL")
                show_step_result(temp_text, "FAIL")
                MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            else:
                CMM.save_step_result(main_log, temp_text, "PASS")
                show_step_result(temp_text, "PASS")
        CMM.save_data(main_log, "IPMI Node info list\n{0}".format(IPMI_NODE_INFO), timestamp=False)

    def d_check_node_via_snmpv1(self,version="1"):
        if IPMI_NODE_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Node info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getNodeInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        node_info = temp_list[2:]
        temp_text = "Check Node total number"
        if total_num == NODE_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Node total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Node present number"
        if present_num == len(Present_Node):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Node present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for node_id in range(1, int(NODE_NUM) + 1):
            node = "Node{0}".format(node_id)
            is_fail = False
            index = node_id - 1
            temp_snmp = node_info[index]
            temp_ipmi = map(str,IPMI_NODE_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(node,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:2] == temp_ipmi[:2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    # """ 两者差值小于IPMI值 即为PASS """
                    # temp_pwrConsumption = float(temp_snmp[2]) - float(temp_ipmi[2])
                    # if abs(temp_pwrConsumption) <= float(temp_ipmi[2]):
                    if float(temp_snmp[2]) >= 0 and float(temp_ipmi[2]) >= 0:
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

    def e_check_node_via_snmpv2(self,version="2c"):
        if IPMI_NODE_FAIL:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Node info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getNodeInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        node_info = temp_list[2:]
        temp_text = "Check Node total number"
        if total_num == NODE_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Node total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Node present number"
        if present_num == len(Present_Node):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Node present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for node_id in range(1, int(NODE_NUM) + 1):
            node = "Node{0}".format(node_id)
            is_fail = False
            index = node_id - 1
            temp_snmp = node_info[index]
            temp_ipmi = map(str,IPMI_NODE_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(node,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:2] == temp_ipmi[:2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    # """ 两者差值小于IPMI值 即为PASS """
                    # temp_pwrConsumption = float(temp_snmp[2]) - float(temp_ipmi[2])
                    # if abs(temp_pwrConsumption) <= float(temp_ipmi[2]):
                    if float(temp_snmp[2]) >= 0 and float(temp_ipmi[2]) >= 0:
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
        if IPMI_NODE_FAIL:
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

    def g_check_node_via_snmpv3(self,version="3"):
        if IPMI_NODE_FAIL:
            return False
        elif not SET_USER_SNMP:
            return False
        global CASE_PASS
        show_version = version[0]
        temp_text = "- Check Node info via SNMP V{0} -".format(show_version)
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        temp_list = getNodeInfoViaSNMP(version=version)
        total_num = temp_list[0]
        present_num = temp_list[1]
        node_info = temp_list[2:]
        temp_text = "Check Node total number"
        if total_num == NODE_NUM:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            message = "Node total number: {0}".format(total_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        temp_text = "Check Node present number"
        if present_num == len(Present_Node):
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")
        else:
            CASE_PASS = False
            message = "Node present number: {0}".format(present_num)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        for node_id in range(1, int(NODE_NUM) + 1):
            node = "Node{0}".format(node_id)
            is_fail = False
            index = node_id - 1
            temp_snmp = node_info[index]
            temp_ipmi = map(str,IPMI_NODE_INFO[index])
            temp_text = "[{0}] SNMP V{1} info".format(node,show_version)
            compare_flag = False
            if len(temp_snmp) == len(temp_ipmi) == ITEM_NUM:
                if temp_snmp[:2] == temp_ipmi[:2] and temp_snmp[-4:] == temp_ipmi[-4:]:
                    # """ 两者差值小于IPMI值 即为PASS """
                    # temp_pwrConsumption = float(temp_snmp[2]) - float(temp_ipmi[2])
                    # if abs(temp_pwrConsumption) <= float(temp_ipmi[2]):
                    if float(temp_snmp[2]) >= 0 and float(temp_ipmi[2]) >= 0:
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
        CMM.show_message(format_item(message), color="green", timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD,
                                               csrf_token=CSRFToken)
        if status == 0:
            show_step_result(message, "PASS")
            CMM.save_step_result(main_log, message, "PASS")
        else:
            show_step_result(message, "FAIL")
            CMM.save_step_result(main_log, message, "FAIL")

    def z_finish(self):
        CMM.save_data(MAIN_LOG, "{0} {1}".format("PASS:" if CASE_PASS else "FAIL:", module_name.replace("_", " ")))
        infos = map(lambda x: "INFO: {0}".format(x), MAIN_LOG_list)
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