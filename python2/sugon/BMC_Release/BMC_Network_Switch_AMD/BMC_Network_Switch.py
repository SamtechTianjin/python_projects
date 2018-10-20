# -*- coding:utf-8 -*-

import os,sys
import re
import json
import argparse
import time,datetime
import copy
from common import BMC,Remote
from console_show import show_title

"""
通过IPMI|WEB|BIOS方式变换BMC网络
"""

LAN_INFO = {
    "1": "dedicate",
    "8": "share"
}

class SwitchViaIPMI(BMC):
    ip_format = "((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){3}(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"
    def __init__(self,bmcip,lan,username,password):
        super(SwitchViaIPMI, self).__init__()
        self.bmcip = bmcip
        self.lan = lan
        self.username = username
        self.password = password
        self.ipmitool = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(self.bmcip,self.username,self.password)
    def check_LAN_state(self,flag,retry_count=1):
        count = 0
        source,ip = None,None
        while count < retry_count:
            cmd = "{0} lan print {1}".format(self.ipmitool,self.lan)
            status,output = self.run_command(cmd)
            if status == 0: break
            count += 1
        else:
            self.show_message("Collect BMC LAN info FAIL !",color="red")
            return False
        for line in output.splitlines():
            if re.search(r'IP Address Source\s+:.*$',line,re.IGNORECASE):
                try:
                    source = re.search(r'static|dhcp|Unspecified',line,re.IGNORECASE).group()
                except Exception: pass
                else:
                    if source.upper() != flag.upper(): source = None
            elif re.search(r'IP Address\s+:.*$',line,re.IGNORECASE):
                try:
                    ip = re.search(r'{0}'.format(self.ip_format),line).group()
                except Exception: pass
                else:
                    if not ip.startswith("10."): ip = None
        return True if source and ip else False
    def set_LAN_state(self,state):
        is_ok = True
        if state.upper() == "DHCP":
            cmd = "{0} lan set {1} ipsrc dhcp".format(self.ipmitool,self.lan)
            status,output = self.run_command(cmd)
            if status == 0:
                pass
                # self.show_message("[LAN {0}] Set DHCP state OK.".format(self.lan),color="green")
            else:
                self.show_message("[LAN {0}] Set DHCP state FAIL !\n{1}".format(self.lan,output),color="red")
                is_ok = False
        elif state.upper() == "STATIC":
            netmask = "255.255.255.0"
            check_cmd = "{0} lan print {1}".format(self.ipmitool,self.lan)
            status,output = self.run_command(check_cmd)
            if status == 0:
                for line in output.splitlines():
                    m = re.search(r'Subnet Mask\s+:.*$',line,re.IGNORECASE)
                    if m:
                        try:
                            netmask = re.search(r'{0}'.format(self.ip_format),line).group()
                        except Exception: pass
                        break
            cmds = [
                "{0} lan set {1} ipsrc static".format(self.ipmitool,self.lan),              # return 0
                "{0} lan set {1} ipaddr {2}".format(self.ipmitool,self.lan,self.bmcip),     # return 1
                "{0} lan set {1} netmask {2}".format(self.ipmitool,self.lan,netmask)        # return 1
            ]
            for index,cmd in enumerate(cmds):
                status,output = self.run_command(cmd)
                time.sleep(3)
                if status != 0 and index == 0:
                    self.show_message("[LAN {0}] Set Static state FAIL !\n{1}".format(self.lan,output),color="red")
                    is_ok = False
                    break
            else:
                pass
                # self.show_message("[LAN {0}] Set Static state OK.".format(self.lan),color="green")
        return is_ok
    @classmethod
    def main(cls,bmcip,lan,username,password,method,interval):
        expect_state = None
        switch = cls(bmcip,lan,username,password)
        start_time = datetime.datetime.now()
        while cls.calc_time_interval(start_time,datetime.datetime.now()) < StressTime:
            ping_pass = Remote.ping_test(switch.bmcip)
            if not ping_pass:
                cls.show_message("Please check BMC Network, exit...",color="red")
                sys.exit(1)
            check_pass = cls.retry_BMC(switch.bmcip,switch.username,switch.password)
            if not check_pass:
                cls.show_message("BMC status is FAIL !",color="red")
                sys.exit(2)
            time.sleep(20)
            if switch.check_LAN_state("DHCP"):
                current_state = "DHCP"
                cls.show_message("[LAN {0}] Current BMC state: DHCP".format(switch.lan))
                if expect_state:
                    if current_state != expect_state:
                        message = "Switched to {0} FAIL !".format(current_state)
                        cls.show_message(message,color="red")
                        break
                    else:
                        message = "Switched to {0} PASS !".format(current_state)
                        cls.show_message(message,color="green")
                set_pass = switch.set_LAN_state("Static")
                expect_state = "Static"
            elif switch.check_LAN_state("Static"):
                current_state = "Static"
                cls.show_message("[LAN {0}] Current BMC state: Static".format(switch.lan))
                if expect_state:
                    if current_state != expect_state:
                        message = "Switched to {0} FAIL !".format(current_state)
                        cls.show_message(message,color="red")
                        break
                    else:
                        message = "Switched to {0} PASS !".format(current_state)
                        cls.show_message(message,color="green")
                set_pass = switch.set_LAN_state("DHCP")
                expect_state = "DHCP"
            else:
                cls.show_message("BMC state is neither DHCP nor Static.",color="yellow")
                break
            if not set_pass:
                break
            time.sleep(interval)
        else:
            cls.show_message("[{0}] BMC Network Switch: PASS".format(method),color="green")
            if switch.check_LAN_state("Static"):
                switch.set_LAN_state("DHCP")
                message = "Set BMC to DHCP state, please wait..."
                cls.show_message(message)
                time.sleep(interval)
            sys.exit(0)
        cls.show_message("[{0}] BMC Network Switch: FAIL".format(method),color="red")

class SwitchViaWEB(SwitchViaIPMI):
    def __init__(self,bmcip,lan,username,password):
        super(SwitchViaWEB, self).__init__(bmcip,lan,username,password)
        self.request_payload = {
            "channel_number": 1,
            "id": 1,
            "interface_name": "",
            "ipv4_address": "",
            "ipv4_dhcp_enable": 1,
            "ipv4_enable": 1,
            "ipv4_gateway": "",
            "ipv4_subnet": "",
            "ipv6_address": "::",
            "ipv6_dhcp_enable": 1,
            "ipv6_enable": 1,
            "ipv6_gateway": "::",
            "ipv6_index": 0,
            "ipv6_prefix": "0",
            "lan_enable": 1,
            "mac_address": "",
            "vlan_enable": 0,
            "vlan_id": "0",
            "vlan_priority": "0"
        }
    def set_LAN_state(self,state):
        is_ok = True
        restapi = "http://{0}/api/settings/network/{1}"
        login_cmd = "curl -X POST -d \"username={0}&password={1}\" \"http://{2}/api/session\" -c cookie 2>/dev/null".format(self.username,self.password,self.bmcip)
        status,output = self.run_command(login_cmd)
        if status == 0:
            try:
                output_dict = json.loads(output.strip())
            except Exception as e:
                self.show_message("[Login exception]\n{0}".format(e),color="red")
                return False
            else:
                if output_dict.get("ok",None) != 0:
                    self.show_message("Login BMC FAIL via curl !",color="red")
                    return False
                csrf_token = output_dict.get("CSRFToken",None)
                if not csrf_token:
                    self.show_message("Get CSRFToken FAIL !",color="red")
                    return False
        else:
            self.show_message("Login BMC FAIL via curl !\n{0}".format(output),color="red")
            return False
        logout_cmd = 'curl -X DELETE -H "X-CSRFTOKEN:{0}" "http://{1}/api/session" -b cookie 2>/dev/null'.format(csrf_token,self.bmcip)
        request_payload = copy.deepcopy(self.request_payload)
        if self.lan == "1":
            request_payload["channel_number"] = 1
            request_payload["id"] = 2
            request_payload["interface_name"] = "eth1"
            restapi = restapi.format(self.bmcip, 2)
        elif self.lan == '8':
            request_payload["channel_number"] = 8
            request_payload["id"] = 1
            request_payload["interface_name"] = "eth0"
            restapi = restapi.format(self.bmcip, 1)
        if state.upper() == "DHCP":
            request_payload["ipv4_dhcp_enable"] = 1
            request_payload["ipv4_enable"] = 1
            request_payload["ipv6_dhcp_enable"] = 1
            request_payload["ipv6_enable"] = 1
        elif state.upper() == "STATIC":
            netmask = "255.255.255.0"
            gateway = ""
            check_cmd = "{0} lan print {1}".format(self.ipmitool,self.lan)
            status,output = self.run_command(check_cmd)
            if status == 0:
                for line in output.splitlines():
                    if re.search(r'Subnet Mask\s+:.*$',line,re.IGNORECASE):
                        try:
                            netmask = re.search(r'{0}'.format(self.ip_format),line).group()
                        except Exception: pass
                    elif re.search(r'Default Gateway IP\s+:.*$',line,re.IGNORECASE):
                        try:
                            gateway = re.search(r'{0}'.format(self.ip_format),line).group()
                        except Exception: pass
            request_payload["ipv4_dhcp_enable"] = 0
            request_payload["ipv4_enable"] = 1
            request_payload["ipv4_address"] = self.bmcip
            request_payload["ipv4_subnet"] = netmask
            request_payload["ipv4_gateway"] = gateway
            request_payload["ipv6_dhcp_enable"] = 1
            request_payload["ipv6_enable"] = 1
        set_cmd = "curl -X PUT -H \"Content-Type: application/json\" -H \"X-CSRFTOKEN: {0}\" -d \"{1}\" {2} -b cookie >/dev/null".format(csrf_token,request_payload,restapi)
        status,output = self.run_command(set_cmd)
        if status != 0:
            is_ok = False
            self.show_message("[LAN {0}] Set {1} FAIL !\n{2}".format(self.lan,state.upper(),output),color="red")
        status,output = self.run_command(logout_cmd)
        if status == 0:
            try:
                output_dict = json.loads(output.strip())
            except Exception as e:
                self.show_message("[Logout exception]\n{0}".format(e), color="red")
                return False
            else:
                if output_dict.get("ok",None) != 0:
                    self.show_message("Logout BMC FAIL via curl !",color="red")
                    return False
        else:
            self.show_message("Logout BMC FAIL via curl !\n{0}".format(output),color="red")
            return False
        if is_ok:
            pass
            # self.show_message("[LAN {0}] Set {1} state OK.".format(self.lan,state))
        return is_ok

class SwitchViaBIOS(SwitchViaIPMI):
    def __init__(self,bmcip,lan,username,password):
        super(SwitchViaBIOS, self).__init__(bmcip,lan,username,password)
    def set_LAN_state(self,state):
        host_connection_ok = False
        remote = Remote(Host_IP,Host_USERNAME,HOST_PASSWORD,ssh_count=6,ssh_interval=15,ping_count=6,ping_interval=60)
        try:
            remote.init_ssh()
            if remote.loop_ping():
                if remote.loop_check_ssh_work():
                    host_connection_ok = True
                    message = "[{0}] Host Network is OK !".format(Host_IP)
                    BMC.show_message(message,color="green")
                else:
                    message = "[{0}] SSH FAIL !".format(Host_IP)
                    BMC.show_message(message,color="red")
            else:
                message = "[{0}] Ping FAIL !".format(Host_IP)
                BMC.show_message(message, color="red")
        except Exception as e:
            message = "Check Host Network FAIL!\n{0}".format(e)
            BMC.show_message(message, color="red")
        finally:
            remote.close_ssh()
        if host_connection_ok:
            collect_cmd = "chmod +x SCELNX_64 && ./SCELNX_64 /o /s bios.txt"
            files = ["SCELNX_64","Switch_via_SCELNX.py"]
            upload_ok = True
            for f in files:
                f_upload_ok = Remote.sftp_upload_file(Host_IP,Host_USERNAME,HOST_PASSWORD,f,"/root/{0}".format(f))
                if not f_upload_ok:
                    upload_ok = False
            if upload_ok:
                status,output = Remote.ssh_run_cmd(collect_cmd,Host_IP,Host_USERNAME,HOST_PASSWORD)
                if status != 0 and status != 1:
                    message = "Collect BIOS info FAIL !\n{0}".format(output)
                    BMC.show_message(message,color="red")
                    return False

                if state == "DHCP":
                    modify_cmd = "python {0} DHCP {1}".format(files[1],LAN_INFO[self.lan])
                elif state == "Static":
                    subnet = "255.255.255.0"
                    gw = "0.0.0.0"
                    check_cmd = "{0} lan print {1}".format(self.ipmitool,self.lan)
                    status,output = self.run_command(check_cmd)
                    if status == 0:
                        for line in output.splitlines():
                            if re.search(r'Subnet Mask\s+:.*$', line, re.IGNORECASE):
                                try:
                                    subnet = re.search(r'{0}'.format(self.ip_format), line).group()
                                except Exception:
                                    pass
                            elif re.search(r'Default Gateway IP\s+:.*$', line, re.IGNORECASE):
                                try:
                                    gw = re.search(r'{0}'.format(self.ip_format), line).group()
                                except Exception:
                                    pass
                    modify_cmd = "python {0} Static {1} {2} {3} {4}".format(files[1],LAN_INFO[self.lan],self.bmcip,subnet,gw)
                else: modify_cmd = ""
                writein_cmd = "./SCELNX_64 /i /s newbios.txt"
                cmds = [modify_cmd,writein_cmd]
                for cmd in cmds:
                    status,output = Remote.ssh_run_cmd(cmd,Host_IP,Host_USERNAME,HOST_PASSWORD)
                    if status != 0 and status != 1:
                        message = "[{0}] Run FAIL !\n{1}".format(cmd,output)
                        BMC.show_message(message,color="red")
                        return False
                    else:
                        message = "[{0}] Run successfully.".format(cmd)
                        BMC.show_message(message,color="green")
                power_cycle_cmd = "{0} chassis power cycle".format(self.ipmitool)
                status,output = self.run_command(power_cycle_cmd)
                if status == 0:
                    message = "Power cycle, please wait..."
                    BMC.show_message(message)
                else:
                    message = "Power cycle FAIL !"
                    BMC.show_message(message,color="red")
                    return False
            else:
                return False
        else:
            return False
        return True

def collect_arguments():
    parser = argparse.ArgumentParser(description="The script switches BMC network via IPMI|WEB|BIOS.",epilog="")
    parser.add_argument("-V","--version",dest="version",action="version",version="version 01",help="show program's version number and exit")
    parser.add_argument("-T","--time",metavar="time",dest="time",type=int,default=43200,action="store",help="BMC stress time, default: 43200s")
    parser.add_argument("-L","--lan",metavar="lan",dest="lan",type=str,action="store",default="1",help="BMC lan number, default: 1")
    parser.add_argument("-B","--bmc",metavar="bmcip",dest="bmcip",type=str,action="store",help="BMC IP address")
    parser.add_argument("-M","--method",metavar="method",dest="method",type=str,action="store",default="IPMI",help="BMC Network switch method such as IPMI|WEB|BIOS, default: IPMI")
    parser.add_argument("-U","--username",metavar="username",dest="username",type=str,default="admin",action="store",help="BMC username, default: admin")
    parser.add_argument("-P","--password",metavar="password",dest="password",type=str,default="admin",action="store",help="BMC password, default: admin")
    parser.add_argument("-H","--host",metavar="hostip",dest="hostip",type=str,action="store",help="OS IP address")
    parser.add_argument("--user",metavar="hostuser",dest="hostuser",type=str,default="root",action="store",help="OS username, default: root")
    parser.add_argument("--pwd",metavar="hostpwd",dest="hostpwd",type=str,default="111111",action="store",help="OS password, default: 111111")
    arguments = vars(parser.parse_args())
    return arguments


if __name__ == '__main__':
    arguments = collect_arguments()
    BMC_IP,StressTime,LAN_NUMBER,METHOD,USERNAME,PASSWORD = [arguments.get(item,None) for item in ["bmcip","time","lan","method","username","password"]]
    if METHOD.upper() in ["IPMI","WEB","BIOS"]:
        show_title("BMC Network Switch -- {0}".format(METHOD))
        if not BMC_IP:
            BMC.show_message("Please input BMC IP !",timestamp=False,color="red")
            sys.exit(1)
    else:
        BMC.show_message("Please input -M IPMI|WEB|BIOS !",timestamp=False,color="red")
        sys.exit(1)
    if METHOD.upper() == "IPMI":
        SwitchViaIPMI.main(BMC_IP,LAN_NUMBER,USERNAME,PASSWORD,"IPMI",180)
    elif METHOD.upper() == "WEB":
        SwitchViaWEB.main(BMC_IP,LAN_NUMBER,USERNAME,PASSWORD,"WEB",180)
    elif METHOD.upper() == "BIOS":
        Host_IP,Host_USERNAME,HOST_PASSWORD = [arguments.get(item,None) for item in ["hostip", "hostuser", "hostpwd"]]
        if not Host_IP:
            BMC.show_message("Please input Host IP !",timestamp=False,color="red")
            sys.exit(1)
        SwitchViaBIOS.main(BMC_IP,LAN_NUMBER,USERNAME,PASSWORD,"BIOS",300)
