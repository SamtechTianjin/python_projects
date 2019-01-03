# -*- coding:utf-8 -*-
__author__ = "Sam"

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
LAN = config.LAN

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_NETWORK_API = "/api/cmminfo/network/"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
API接口返回值
[ { "interface_name": "eth1", "channel_number": 8, "lan_enable": 1, "mac_address": "00:3A:3B:3C:3D:3E", "ipv4_enable": 1, "ipv4_dhcp_enable": 0, "ipv4_address": "10.0.22.234", "ipv4_subnet": "255.255.255.0", "ipv4_gateway": "10.0.22.254", "ipv6_enable": 0, "ipv6_dhcp_enable": 1, "ipv6_address": "::", "ipv6_index": 0, "ipv6_prefix": 0, "ipv6_gateway": "::" } ]
"mac_address", "ipv4_dhcp_enable", "ipv4_address", "ipv4_subnet", "ipv4_gateway"
"""



def getNetworkInfoViaAPI():
    is_fail = False
    network_info = {}
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,GET_NETWORK_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Get Network info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_fail = True
            message = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            CMM.save_data(main_log,message,timestamp=False)
        else:
            if isinstance(json_data,dict) and json_data.get("error"):
                is_fail = True
            else:
                network_info = json_data
                CMM.save_data(MAIN_LOG,"NETWORK_INFO: {0}".format(network_info),timestamp=False)
    else:
        is_fail = True
    return {} if is_fail else network_info

def getNetworkInfoViaOEM():
    is_fail = False
    networkInfo = {}
    cmd = "{0} lan print {1}".format(IPMITOOL,LAN)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[OEM] Get Network Info\n{0}\nreturncode: {1}\n{2}".format(cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        for line in output.splitlines():
            if re.search(r'MAC Address',line,re.IGNORECASE):
                mac_address = line.split(":",1)[-1].strip()
                networkInfo["mac_address"] = mac_address.upper()
            elif re.search(r'Source',line,re.IGNORECASE):
                if re.search(r'dhcp',line,re.IGNORECASE):
                    ipv4_dhcp_enable = 1
                else:
                    ipv4_dhcp_enable = 0
                networkInfo["ipv4_dhcp_enable"] = ipv4_dhcp_enable
            elif re.search(r'IP Address',line,re.IGNORECASE):
                ipv4_address = line.split(":",1)[-1].strip()
                networkInfo["ipv4_address"] = ipv4_address
            elif re.search(r'Subnet Mask',line,re.IGNORECASE):
                ipv4_subnet = line.split(":",1)[-1].strip()
                networkInfo["ipv4_subnet"] = ipv4_subnet
            elif re.search(r'Default Gateway IP',line,re.IGNORECASE):
                ipv4_gateway = line.split(":",1)[-1].strip()
                networkInfo["ipv4_gateway"] = ipv4_gateway
    else:
        is_fail = True
    return {} if is_fail else networkInfo




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

    def c_compare_network_info(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        message = "- Compare Network info -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        CMM.save_data(main_log, message, timestamp=False)
        temp_text = message.strip(" -")
        is_FAIL = False
        tempData = getNetworkInfoViaAPI()
        """ 判断API得到的返回值是 dict 或 list """
        API_data = {}
        if isinstance(tempData,list):
            for tempDict in tempData:
                if tempDict.get("channel_number") == LAN:
                    API_data = tempDict
                    break
        elif isinstance(tempData,dict):
            if tempData.get("channel_number") == LAN:
                API_data = tempData
        if not API_data:
            is_FAIL = True
        else:
            OEM_data = getNetworkInfoViaOEM()
            compareList = ["mac_address", "ipv4_dhcp_enable", "ipv4_address", "ipv4_subnet", "ipv4_gateway"]
            for item in compareList:
                apiValue = API_data.get(item)
                oemValue = OEM_data.get(item)
                if apiValue != oemValue:
                    text = "[API] {0}: {1}".format(item,apiValue)
                    MAIN_LOG_list.append(text)
                    CMM.show_message(text,timestamp=False,color="red")
                    text = "[OEM] {0}: {1}".format(item,oemValue)
                    MAIN_LOG_list.append(text)
                    CMM.show_message(text,timestamp=False,color="red")
                    is_FAIL = True
        if is_FAIL:
            CASE_PASS = False
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        else:
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")

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