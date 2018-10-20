# -*- coding:utf-8 -*-

import re
import sys

BIOS_FILE = "bios.txt"
BIOS_FILE_NEW = "newbios.txt"
NETWORK_FLAG = "Configuration Address source"
IP_FLAG = "Station IP address"
SUBNET_FLAG = "Subnet mask"
GATEWAY_FLAG = "Router IP address"
GATEWAY_MAC_FLAG = "Router MAC address"

def BMCNetworkSwitch(state="DHCP",lan="dedicate",ip=None,subnet=None,gw=None):
    with open(BIOS_FILE,"r") as f1, open(BIOS_FILE_NEW,"w") as f2:
        number,DedicateLan,ShareLan,flag,static_flag,argument = 0,1,2,None,None,None
        for line in f1:
            newline = None
            if re.search(r'{0}'.format(NETWORK_FLAG),line,re.IGNORECASE):
                number += 1
                if number == DedicateLan:
                    flag = "dedicate"
                elif number == ShareLan:
                    flag = "share"
                else:
                    flag = "other"
            if flag == lan.lower():
                if re.search(r'Options\s*=\s*\*\[\d+\]Unspecified',line,re.IGNORECASE):
                    newline = re.sub(r'\*\[','[',line)
                if state == "DHCP":
                    if re.search(r'\[\d+\]DynamicBmcDhcp',line,re.IGNORECASE):
                        newline = re.sub(r'\[','*[',line)
                elif state == "Static":
                    if re.search(r'\[\d+\]Static',line,re.IGNORECASE):
                        newline = re.sub(r'\[','*[',line)
                    elif re.search(r'{0}'.format(IP_FLAG),line,re.IGNORECASE):
                        static_flag = "ip"
                        argument = ip
                    elif re.search(r'{0}'.format(SUBNET_FLAG),line,re.IGNORECASE):
                        static_flag = "subnet"
                        argument = subnet
                    elif re.search(r'{0}'.format(GATEWAY_FLAG),line,re.IGNORECASE):
                        static_flag = "gw"
                        argument = gw
                if static_flag:
                    if re.search(r'Value\s*=.*',line,re.IGNORECASE):
                        newline = re.sub(r'=.*', '="{0}"'.format(argument), line)
                        static_flag,argument = None,None
            if newline:
                f2.write(newline)
            else:
                f2.write(line)

if __name__ == '__main__':
    # BMCNetworkSwitch(state="DHCP",lan="dedicate")
    # BMCNetworkSwitch(state="DHCP",lan="share")
    # BMCNetworkSwitch(state="Static",lan="dedicate",ip="10.0.21.86",subnet="255.255.255.0",gw="10.0.21.254")
    # BMCNetworkSwitch(state="Static",lan="share",ip="10.0.21.86",subnet="255.255.255.0",gw="10.0.21.254")
    if len(sys.argv) == 3:
        state,lan = sys.argv[1:]
        BMCNetworkSwitch(state=state,lan=lan)
    elif len(sys.argv) == 6:
        state,lan,ip,subnet,gw = sys.argv[1:]
        BMCNetworkSwitch(state=state,lan=lan,ip=ip,subnet=subnet,gw=gw)
    else:
        print("Usage: python {0} <DHCP|Static> <dedicate|share> <ip> <subnet> <gw>".format(sys.argv[0]))
        sys.exit(1)
