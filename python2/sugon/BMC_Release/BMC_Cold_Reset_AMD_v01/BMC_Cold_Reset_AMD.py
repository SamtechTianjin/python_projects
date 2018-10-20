#!/usr/bin/env python
# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import argparse
import time
import datetime
import shutil
import commands
import re
import collections
import json
from check_ssh_service import CheckSSHSerivce

def get_args():
    parser = argparse.ArgumentParser(prog=None, usage="", description="The script includes Retry ME function.", epilog="eg: python %s -B 10.2.35.198 -H 10.2.33.145 -L '1,8' -I" %(sys.argv[0]))
    parser.add_argument("-V","--version",dest="version",action="version",version="BMCCR_AMD_V1.0",help="show program's version number and exit")
    parser.add_argument("-T","--time",metavar="time",dest="time",type=int,default=43200,action="store",help="BMC stress time, default: 43200s")
    parser.add_argument("-L","--lan",metavar="lannum",dest="lannum",type=str,action="store",default="1",help="BMC lan number, please add the quotation mark, default: '1', eg: '1,8'")
    parser.add_argument("-B","--bmc",metavar="bmcip",dest="bmcip",type=str,action="store",default="",help="BMC IP address")
    parser.add_argument("--bmcuser",metavar="bmcuser",dest="bmcuser",type=str,default="admin",action="store",help="BMC username, default: admin")
    parser.add_argument("--bmcpasswd",metavar="bmcpasswd",dest="bmcpasswd",type=str,default="admin",action="store",help="BMC password, default: admin")
    """ In-band test """
    parser.add_argument("-I", "--inband", dest="inband", action="store_true", default=False,help="The in-band test, default: False")
    parser.add_argument("-H", "--host", metavar="hostip", dest="hostip", type=str, action="store", default="", help="OS IP address")
    parser.add_argument("--osuser",metavar="osuser",dest="osuser",type=str,default="root",action="store",help="OS username, default: root")
    parser.add_argument("--ospasswd",metavar="ospasswd",dest="ospasswd",type=str,default="111111",action="store",help="OS password, default: 111111")
    args = vars(parser.parse_args())
    return args

def get_time_string():
    # return time.strftime(timestamp_format, time.localtime())
    return datetime.datetime.now().strftime(timestamp_format)

def get_time_interval(start, end):
    if isinstance(start, str):
        start = datetime.datetime.strptime(start, timestamp_format)
    if isinstance(end, str):
        end = datetime.datetime.strptime(end, timestamp_format)
    interval = (end - start).days * 86400 + (end - start).seconds
    return interval     # return int

def calc_time(base, delta):
    if isinstance(base, str):
        base = datetime.datetime.strptime(base, timestamp_format)
    delta = datetime.timedelta(seconds=delta)
    obj_time = base + delta
    obj_time_str = obj_time.strftime(timestamp_format)
    return obj_time_str

def show_pass_message(message):
    print "%s\t\033[1;32m%s\033[0m" %(get_time_string(), message)

def show_fail_message(message):
    print "%s\t\033[1;31m%s\033[0m" %(get_time_string(), message)

def show_warn_message(message):
    print "%s\t\033[1;33m%s\033[0m" % (get_time_string(), message)

def show_message(message):
    print "%s\t%s" % (get_time_string(), message)

def save_data(filename, data, flag="a", timestamp=True):
    if timestamp:
        data = "%s\t%s\n" %(get_time_string(), data)
    else:
        data = "%s\n" %data
    if flag == "w":
        f = open(filename, "w")
    else:
        f = open(filename, "a")
    f.write(data)
    f.close()

def run_cmd(cmd, filename=None):
    status, output = commands.getstatusoutput(cmd)
    if status != 0:
        msg = "[%s] Run FAIL !" %cmd
    else:
        msg = "[%s] Run successfully." %cmd
    if filename:
        msg = "\n".join([msg, output])
        save_data(filename, msg)
    return status, output.strip()

def backup(directry):
    if not os.path.exists(directry):
        os.makedirs(directry)
    for f in os.listdir("."):
        if f.endswith(".log"):
            shutil.move(f, os.path.join(directry, f))

def config_PATH():
    ret = run_cmd("echo $PATH")
    if ret[0] == 0:
        OS_PATH = ret[-1]
        if not re.search(r'sbin', OS_PATH):
            OS_PATH = ":".join([OS_PATH, "/usr/local/sbin:/sbin:/usr/sbin"])
            ret = run_cmd("export PATH=%s" %OS_PATH, main_log)
            if ret[0] != 0:
                show_fail_message("[export $PATH] Run FAIL !")
                sys.exit(1)
    else:
        show_fail_message("[echo $PATH] Run FAIL !")
        sys.exit(1)

def check_power_status():
    cmd = "%s chassis power status" %IPMITOOL
    retry_counts = 3
    count = 0
    while count < retry_counts:
        ret = run_cmd(cmd)
        if ret[0] != 0:
            show_fail_message("[%s] Run FAIL !" %cmd)
            sys.exit(1)
        else:
            power_status = re.search(r'on|off', ret[-1], re.IGNORECASE).group()
            if power_status == "off":
                power_on()
            elif power_status == "on":
                save_data(main_log, "Chassis Power is on.")
                break
        count += 1
        time.sleep(3)
    else:
        msg = "Chassis power is still off after 3 tries !"
        show_fail_message(msg)
        save_data(main_log, msg)
        sys.exit(1)

def power_on():
    cmd = "%s chassis power on" %IPMITOOL
    ret = run_cmd(cmd)
    if ret[0] != 0:
        show_fail_message("[%s] Run FAIL !" %cmd)

def ping_test(flag="", IP=None, username=None, password=None):
    if flag == "BMC":
        IP = BMC_IP
        ping_flag = CheckSSHSerivce(BMC_IP, BMC_username, BMC_password).loop_ping()
    elif flag == "Host":
        IP = HOST_IP
        ping_flag = CheckSSHSerivce(HOST_IP, HOST_username, HOST_password, ping_interval=10, ping_count=30).loop_ping()
    else:
        ping_flag = CheckSSHSerivce(IP, username, password).loop_ping()
    if not ping_flag:
        msg = "[%s] ping %s IP FAIL !" % (IP, flag)
        show_fail_message(msg)
        save_data(main_log, msg)
        return False
    msg = "[%s] ping %s IP PASS !" % (IP, flag)
    show_pass_message(msg)
    save_data(main_log, msg)
    return True

def check_BMC(interval=10, timeout=300):
    cmd = "%s raw 0x06 0x01" %IPMITOOL
    start_time = datetime.datetime.now()
    t = 0
    while t <= timeout:
        ret = run_cmd(cmd)
        end_time = datetime.datetime.now()
        t = get_time_interval(start_time, end_time)
        if ret[0] == 0:
            break
        else:
            time.sleep(interval)
    else:
        msg = "BMC status is still FAIL after %s seconds." %timeout
        show_fail_message(msg)
        save_data(main_log, msg)
        return False
    msg = "BMC status is OK."
    show_pass_message(msg)
    save_data(main_log, msg)
    return True

def parse_data(data):
    tmp_dict = collections.OrderedDict()
    if ":" not in data:
        if "\n" in data:
            tmp_list = list()
            data_list = data.split("\n")
            for d in data_list:
                tmp_list.append(d.strip())
            return "list", tmp_list
        return "string", data
    try:
        data_list = data.split("\n")
        for d in data_list:
            # tmp_list = list()
            d = d.strip()
            if not d: continue
            elif ":" in d:
                if re.search(r'[\w().]+\s*:\s*[\w().]+', d):
                    dd = d.split(":", 1)
                    tmp_dict[dd[0].strip()] = dd[-1].strip()
                elif d.endswith(":"):
                    key = d.split(":")[0].strip()
                    tmp_list = list()
                    tmp_dict[key] = tmp_list
            else:
                tmp_list.append(d)
    except Exception as e:
        print e
    return "dict", tmp_dict

def check_lan_info(cmd, mode=1, retry_counts=3, interval=10, flag="lan"):
    gateway_ip = None
    gateway_mac = None
    cmd = "%s %s" %(cmd, mode)
    count = 0
    while count < retry_counts:
        if flag == "lan":
            ret = run_cmd(cmd)
        else:
            ret = CheckSSHSerivce.ssh_run_cmd(cmd, HOST_IP, HOST_username, HOST_password)
        if ret[0] == 0:
            data = ret[-1]
            m_list = re.findall(r'Default Gateway IP.*|Default Gateway MAC.*', data)
            if m_list:
                for item in m_list:
                    if re.search(r'ip', item, re.IGNORECASE):
                        gateway_ip = item.split(":")[-1].strip()
                    elif re.search(r'mac', item, re.IGNORECASE):
                        gateway_mac = item.split(":", 1)[-1].strip()
            if gateway_ip and gateway_ip != "0.0.0.0" and gateway_mac and gateway_mac != "00:00:00:00:00:00":
                break
        else:
            time.sleep(interval)
        count += 1
    else:
        return 1, {"Default Gateway IP": gateway_ip, "Default Gateway MAC": gateway_mac}
    return 0, {"Default Gateway IP": gateway_ip, "Default Gateway MAC": gateway_mac}

def retry_test(cmd, retry_counts=3, interval=3, flag="lan"):
    count = 0
    ret = [1,"default"]
    while count < retry_counts:
        if flag == "lan":
            ret = run_cmd(cmd)
        else:
            ret = CheckSSHSerivce.ssh_run_cmd(cmd, HOST_IP, HOST_username, HOST_password)
        if ret[0] == 0:
            break
        else:
            time.sleep(interval)
        count += 1
    else:
        return 1, ret[-1]
    return 0, ret[-1]

def collect_data(base=False, flag="lan", loop_num=None):
    if base and flag == "lan":
        msg = "Collect baseline start..."
        cmds = ipmi_lan_cmds
        save_data(main_log, msg)
    elif not base and flag == "lan":
        msg = "[loop %s] Collect data start...(LAN)" %loop_num
        cmds = ipmi_lan_cmds
        save_data(main_log, msg)
    elif not base and flag == "local":
        cmds = ipmi_local_cmds
        msg = "[loop %s] Collect data start...(local)" % loop_num
    else:
        msg,cmds = "",{}
    show_message(msg)
    data = collections.OrderedDict()
    for name,cmd in cmds.iteritems():
        if name == "lan info":
            tmp = collections.OrderedDict()
            for mode in modes:
                ret = check_lan_info(cmd, mode=mode, flag=flag)
                if ret[0] == 0:
                    show_pass_message("lan %s info OK." %mode)
                else:
                    show_warn_message("lan %s info Error !\n%s" %(mode, ret[-1]))
                tmp["lan %s"%mode] = ret[-1]
            data[name] = tmp
            continue
        else:
            if flag == "lan":
                ret = run_cmd(cmd)
            else:
                if name == "sol info":
                    continue
                ret = CheckSSHSerivce.ssh_run_cmd(cmd, HOST_IP, HOST_username, HOST_password)
            if ret[0] != 0:
                show_fail_message("[%s] Run FAIL !" % cmd)
                data[name] = str(ret[-1])
                continue
        show_message("[%s] Run successfully !" % cmd)
        data[name] = parse_data(ret[-1])[-1]
    return data

def continue_test():
    """ continue or exit """
    while True:
        user_choice = raw_input("\033[1;33m Please check baseline, continue test (yes/no): \033[0m")
        user_choice = user_choice.strip()
        if user_choice.lower() == "yes" or user_choice.lower() == "y":
            msg = "The baseline is OK, continue test..."
            show_pass_message(msg)
            save_data(main_log, msg)
            break
        elif user_choice.lower() == "no" or user_choice.lower() == "n":
            msg = "Exit test..."
            show_fail_message(msg)
            save_data(main_log, msg)
            sys.exit(0)
        else:
            print "\033[1;31m Input error, please input yes or no !\033[0m"

def init():
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    backup(backup_dir)
    show_message("%s start..." %Test_name)
    save_data(main_log, "%s start..." %Test_name, flag="w")
    ping_bmc = ping_test(flag="BMC")
    if not ping_bmc:
        sys.exit(1)
    bmc_status = check_BMC()
    if not bmc_status:
        sys.exit(1)
    check_power_status()
    """ In-band test """
    if In_Band:
        ping_host = ping_test(flag="Host")
        if not ping_host:
            sys.exit(1)
    config_PATH()

def save_time(filename, flag, timestamp=None):      # timestamp: str
    if not os.path.exists(filename):
        time_dict = dict()
    else:
        time_dict = file_to_dict(filename)
    if not timestamp:
        time_dict[flag] = get_time_string()
    else:
        time_dict[flag] = timestamp
    save_data(filename, json.dumps(time_dict, indent=4), flag="w", timestamp=False)
    return time_dict[flag]

def file_to_dict(filename):
    f = open(filename, "r")
    data = f.read().strip()
    f.close()
    unicode_dic = json.loads(data)
    return unicode_convert(unicode_dic)

def unicode_convert(data):
    if isinstance(data, list):
        return [unicode_convert(item) for item in data]
    elif isinstance(data, dict):
        return {unicode_convert(key): unicode_convert(value) for key,value in data.items()}
    elif isinstance(data, unicode):
        return data.encode(encoding="utf-8")
    else:
        return data

def collect_log(filename=None, folder=None, end=False):
    if end:
        os.chdir(current_path)
        for f in os.listdir("."):
            if f.endswith(".log") and not f.startswith(Test_name) or f == "cookie":
                shutil.move(f, os.path.join(log_dir, f))
    else:
        if not os.path.exists(folder):
            os.makedirs(folder)
        shutil.move(filename, os.path.join(folder, filename))

def compare_res(data1, data2, loop_num, flag="lan"):
    """ data1: baseline, data2: loop data """
    fail_flag = False
    no_check = list()
    if flag == "local":
        no_check.append("sol info")
    for name,res in data1.iteritems():
        compare_result = dict()
        compare_result["baseline"] = list()
        compare_result["loop_%s" % loop_num] = list()
        if data2.has_key(name):
            res2 = data2[name]
            if res == res2:
                continue
            elif name == "lan info":
                continue
            elif isinstance(res, str) or isinstance(res2, str):
                compare_result["baseline"].append(res)
                compare_result["loop_%s" % loop_num].append(res2)
            elif isinstance(res, dict) and isinstance(res2, dict):
                for key, value1 in res.iteritems():
                    value2 = res2[key]
                    if value1 == value2:
                        continue
                    elif key in white_list:
                        continue
                    else:
                        compare_result["baseline"].append({key: value1})
                        compare_result["loop_%s" % loop_num].append({key: value2})
        else:
            if name in no_check:
                continue
            else:
                compare_result["baseline"].append(res)
                compare_result["loop_%s" % loop_num].append("None")
        if compare_result["baseline"]:
            msg = "%s Error !\n%s" %(name, json.dumps(compare_result, indent=4))
            show_fail_message(msg)
            save_data(main_log, msg)
            fail_flag = True
    return fail_flag

def loop_check(baseline, loop_num, flag="lan"):
    global fail_flag
    loop_log = "Loop_%s_%s.log" % (loop_num, BMC_IP)
    if flag == "local":
        ping_status = CheckSSHSerivce(HOST_IP, HOST_username, HOST_password, ping_interval=10, ping_count=30).loop_ping()
        if ping_status:
            msg = "[loop %s] Ping Host IP PASS !" % loop_num
            show_pass_message(msg)
            save_data(main_log, msg)
            ssh_status = CheckSSHSerivce(HOST_IP, HOST_username, HOST_password, ssh_interval=10, ssh_count=9).loop_check_ssh_work()
            if ssh_status:
                msg = "[loop %s] Check SSH service PASS !" %loop_num
                show_pass_message(msg)
                save_data(main_log, msg)
            else:
                msg = "[loop %s] Check SSH service FAIL !" %loop_num
                show_fail_message(msg)
                save_data(main_log, msg)
                sys.exit(1)
        else:
            msg = "[loop %s] Ping Host IP FAIL !" % loop_num
            show_fail_message(msg)
            save_data(main_log, msg)
            sys.exit(1)
        check_bmc_driver()
    loop_data = collect_data(loop_num=loop_num, flag=flag, base=False)
    loop_data_str = json.dumps(loop_data, indent=4)
    if flag == "lan":
        save_data(loop_log, "[IPMI_LAN]\n%s" %loop_data_str, flag="w", timestamp=False)
    else:
        save_data(loop_log, "[IPMI_Local]\n%s" %loop_data_str, flag="a", timestamp=False)
    fail_flag = compare_res(baseline, loop_data, loop_num, flag=flag)
    if fail_flag:
        if flag == "lan":
            msg = "[loop %s] iOL FAIL, settings changed !" % (loop_num)
        else:
            msg = "[loop %s] local FAIL, settings changed !" % (loop_num)
        show_fail_message(msg)
    else:
        if flag == "lan":
            msg = "[loop %s] iOL PASS !" % loop_num
        else:
            msg = "[loop %s] local PASS !" % loop_num
        show_pass_message(msg)
    save_data(main_log, msg)
    return loop_log

def check_bmc_driver():
    cmd = "lsmod | grep -i ipmi"
    ret = CheckSSHSerivce.ssh_run_cmd(cmd, HOST_IP, HOST_username, HOST_password)
    if ret[0] == 0:
        ipmi_driver = ["ipmi_si", "ipmi_devintf", "ipmi_msghandler"]
        for driver in ipmi_driver:
            if driver in ret[-1]:
                msg = "Module %s is loaded." %driver
                show_pass_message(msg)
            else:
                msg = "Module %s is not currently loaded !" %driver
                show_fail_message(msg)
            save_data(main_log, msg)
    else:
        msg = "Check ipmi driver FAIL !\n%s" %(ret[-1])
        show_fail_message(msg)
        save_data(main_log, msg)

def check_bmc_service(retry_counts=6, interval=30):
    count = 1
    while count <= retry_counts:
        cmd = "ps -ef | grep -i lighttpd | grep -v grep"
        ret = CheckSSHSerivce.ssh_run_cmd(cmd, BMC_IP, BMC_username, BMC_password)
        if ret[0] == 0:
            if ret[-1]:
                msg = "The lighttpd service is OK."
                show_pass_message(msg)
                save_data(main_log, msg)
                break
            else:
                msg = "The lighttpd service is FAILED !"
                show_fail_message(msg)
                save_data(main_log, msg)
        else:
            msg = "Check lighttpd service FAIL ! Try count: %s/%s" %(count, retry_counts)
            show_fail_message(msg)
            save_data(main_log, msg)
        save_data(main_log, ret[-1], timestamp=False)
        count += 1
        time.sleep(interval)

def bmc_reset(flag="cold"):
    cmd = "%s mc reset %s" %(IPMITOOL, flag)
    ret = run_cmd(cmd, main_log)
    if ret[0] == 0:
        msg = "[%s] BMC %s reset PASS !" %(BMC_IP, flag)
        show_pass_message(msg)
    else:
        msg = "[%s] BMC %s reset FAIL !" % (BMC_IP, flag)
        show_fail_message(msg)
        sys.exit(1)

def check_fan_speed(loop_num):
    cmd = "%s sdr elist" %IPMITOOL
    ret = run_cmd(cmd)
    if ret[0] == 0:
        speed_list = list()
        for i in ret[-1].split("\n"):
            i = i.strip()
            if not i: continue
            m = re.search(r'FAN\d+_Speed.*RPM', i, re.IGNORECASE)
            if m:
                speed_list.append(m.group().split()[-2])
        msg = "[loop %s] FAN_Speed: %s" %(loop_num, speed_list)
        show_message(msg)
    else:
        msg = "Check sdr list FAIL !"
        show_fail_message(msg)
    save_data(main_log, msg)

def check_lan_speed(data):
    if data and data != "0.0.0.0":
        if CheckSSHSerivce(data, BMC_username, BMC_password).loop_ping():
            cmd = "ifconfig -a | grep -B 1 10.2.35.198 | head -n 1 | awk '{print $1}'"
            ret = CheckSSHSerivce.ssh_run_cmd(cmd, data, BMC_username, BMC_password)
            if ret[0] == 0:
                nic_name = ret[-1]
                cmd = "ethtool %s | grep -i speed" %nic_name
                ret = CheckSSHSerivce.ssh_run_cmd(cmd, data, BMC_username, BMC_password)
                if ret[0] == 0:
                    m = re.search(r'speed:.*/s', ret[-1], re.IGNORECASE)
                    if m:
                        speed = m.group().split(":")[-1]
                        return speed

def curl_check(base=False, loop_num=None):
    if base:
        msg = "Collect baseline start...(curl)"
    else:
        msg = "[loop %s] Collect data start...(curl)" %loop_num
    show_message(msg)
    save_data(main_log, msg)
    data = collections.OrderedDict()
    login_cmd = 'curl -X POST -d "username=%s&password=%s" "http://%s/api/session" -c ./cookie 2> /dev/null' %(BMC_username, BMC_password, BMC_IP)
    ret = run_cmd(login_cmd)
    if ret[0] == 0:
        try:
            tmp = unicode_convert(json.loads(ret[-1]))
            csrf_token = tmp["CSRFToken"]
            msg = "Login BMC Web successfully via curl !"
            show_pass_message(msg)
            save_data(main_log, msg)
        except Exception as e:
            print ret
            show_fail_message(str(e))
            return data
    else:
        print ret
        if base:
            msg = "Login BMC Web FAIL via curl !\n%s" %(ret[-1])
        else:
            msg = "[loop %s] Login BMC Web FAIL via curl !\n%s" %(loop_num, ret[-1])
        show_fail_message(msg)
        save_data(main_log, msg)
        return data
    check_list = ["GUID", "prodectname", "prodecttype", "BMCVersion", "CPLDVersion", "BIOSVersion",
                  "LineType", "MACAddress", "IPAddress", "IPSource"]
    logout_cmd = 'curl -X DELETE -H "X-CSRFTOKEN:%s" "http://%s/api/session" -b ./cookie 2> /dev/null' %(csrf_token, BMC_IP)
    serverinfo_cmd = 'curl -X GET -H "X-CSRFTOKEN:%s" "http://%s/api/serverinfo/serverinfo" -b ./cookie 2> /dev/null' %(csrf_token, BMC_IP)
    fwinfo_cmd = 'curl -X GET -H "X-CSRFTOKEN:%s" "http://%s/api/serverinfo/fwinfo" -b ./cookie 2> /dev/null' %(csrf_token, BMC_IP)
    dictlan_cmd = 'curl -X GET -H "X-CSRFTOKEN:%s" "http://%s/api/serverinfo/dictnetinfo" -b ./cookie 2> /dev/null' %(csrf_token, BMC_IP)
    sharelan_cmd = 'curl -X GET -H "X-CSRFTOKEN:%s" "http://%s/api/serverinfo/sharenetinfo" -b ./cookie 2> /dev/null' %(csrf_token, BMC_IP)
    for cmd in serverinfo_cmd, fwinfo_cmd, dictlan_cmd, sharelan_cmd, logout_cmd:
        ret = run_cmd(cmd)
        tmp = dict()
        if ret[0] == 0:
            msg = "[%s] Run successfully !" %cmd
            show_message(msg)
            save_data(main_log, msg)
            try:
                tmp = unicode_convert(json.loads(ret[-1]))
            except Exception as e:
                print ret
                show_fail_message(str(e))
            if cmd == logout_cmd:
                continue
            elif cmd == sharelan_cmd:
                data["share_LineType"] = tmp.get("LineType", None)
                data["share_MACAddress"] = tmp.get("MACAddress", None)
                data["share_IPAddress"] = tmp.get("IPAddress", None)
                # speed = check_lan_speed(data["share_IPAddress"])
                # if speed:
                #     data["share_LanSpeed"] = speed
                # data["share_IPSource"] = tmp.get("IPSource", None)
            elif cmd == dictlan_cmd:
                data["dict_LineType"] = tmp.get("LineType", None)
                data["dict_MACAddress"] = tmp.get("MACAddress", None)
                data["dict_IPAddress"] = tmp.get("IPAddress", None)
                # speed = check_lan_speed(data["dict_IPAddress"])
                # if speed:
                #     data["dict_IPAddress"] = speed
                # data["dict_IPSource"] = tmp.get("IPSource", None)
            else:
                for k,v in tmp.iteritems():
                    if k in check_list:
                        data[k] = v
        else:
            msg = "[%s] Run FAIL !\n%s" %(cmd, ret[-1])
            show_fail_message(msg)
            save_data(main_log, msg)
    return data

def compare_curl_res(data1, data2, loop_num):
    """ data1: baseline """
    fail_flag = False
    res = {"baseline": {}, "loop_data": {}}
    for key,value1 in data1.iteritems():
        if data2.has_key(key):
            value2 = data2[key]
            if value1 == value2:
                continue
            else:
                res["baseline"][key] = value1
                res["loop_data"][key] = value2
                fail_flag = True
        else:
            res["baseline"][key] = value1
            res["loop_data"][key] = None
            fail_flag = True
    if fail_flag:
        msg = "[loop %s] curl check FAIL, settings changed !\n%s" % (loop_num, json.dumps(res, indent=4))
        show_fail_message(msg)
    else:
        msg = "[loop %s] curl check PASS." % loop_num
        show_pass_message(msg)
    save_data(main_log, msg)
    return fail_flag

def main():
    init()
    baseline = collect_data(base=True)
    baseline_str = json.dumps(baseline, indent=4)
    save_data(baseline_log, "[IPMI_baseline]\n%s" %baseline_str, flag="w", timestamp=False)
    curl_baseline = curl_check(base=True)
    curl_baseline_str = json.dumps(curl_baseline, indent=4)
    save_data(baseline_log, "[Curl_baseline]\n%s" %curl_baseline_str, flag="a", timestamp=False)
    collect_log(baseline_log, log_dir)
    print " baseline ".center(80, "#")
    print "\033[1;34m[IPMI]\033[0m"
    print baseline_str
    print "\033[1;34m[Curl]\033[0m"
    print curl_baseline_str
    continue_test()
    start_time = save_time(timestamp_log, flag="start_time")
    expected_end_time = calc_time(start_time, delta=Test_time)
    save_time(timestamp_log, flag="expected_end_time", timestamp=expected_end_time)
    interval = 0
    loop_num = 1
    global fail_flag
    fail_flag = False
    while interval <= Test_time:
        bmc_reset(flag="cold")
        time.sleep(10)
        bmc_status = check_BMC()
        time.sleep(120)
        if not bmc_status:
            sys.exit(1)
        check_bmc_service()
        for n in range(3):
            check_fan_speed(loop_num)
        # sequence: lan -> local -> curl
        loop_log = loop_check(baseline, loop_num, flag="lan")       # ipmi Lan
        """ In-band test """
        if In_Band:
            loop_check(baseline, loop_num, flag="local")            # ipmi Local
        curl_loop_data = curl_check(base=False, loop_num=loop_num)  # curl
        save_data(loop_log, "[Curl]\n%s" %json.dumps(curl_loop_data, indent=4), timestamp=False)
        collect_log(filename=loop_log, folder=log_dir)
        fail_status = compare_curl_res(curl_baseline, curl_loop_data, loop_num)
        if fail_status:
            fail_flag = True
        loop_num += 1
        check_time = datetime.datetime.now()
        interval = get_time_interval(start_time, check_time)
    save_time(timestamp_log, flag="actual_end_time")
    if not fail_flag:
        msg = "%s test finish.  Result: PASS" % Test_name
        show_pass_message(msg)
    else:
        msg = "%s test finish.  Result: FAIL" % Test_name
        show_fail_message(msg)
    save_data(main_log, msg)
    collect_log(end=True)

if __name__ == '__main__':
    Test_name = "BMC_Cold_Reset_AMD_v01"
    current_path = os.path.abspath(os.path.dirname(__file__))
    os.chdir(current_path)
    timestamp_format = "%Y-%m-%d_%H:%M:%S"
    args = get_args()
    if not args["bmcip"]:
        msg = "Please input BMC IP address !"
        show_fail_message(msg)
        print os.popen("python %s --help" %sys.argv[0]).read()
        sys.exit(1)
    BMC_IP, BMC_username, BMC_password, \
    HOST_IP, HOST_username, HOST_password, \
    Test_time, Lan_num, In_Band = \
        [args[item] for item in ["bmcip", "bmcuser", "bmcpasswd", "hostip", "osuser", "ospasswd", "time", "lannum", "inband"]]
    """ In-band test """
    if In_Band:
        if not HOST_IP:
            msg = "Please input Host IP address !"
            show_fail_message(msg)
            sys.exit(1)
    modes = [int(i) for i in Lan_num.split(",")]
    log_dir = "LOG_%s_%s" %(BMC_IP, get_time_string())
    log_dir = os.path.join(current_path, log_dir)
    backup_dir = "BACKUP_%s_%s" %(BMC_IP, get_time_string())
    main_log = "%s_%s.log" %(Test_name, BMC_IP)
    baseline_log = "Baseline_%s.log" %BMC_IP
    timestamp_log = "Timestamp_%s.log" %BMC_IP
    IPMITOOL = "ipmitool -I lanplus -H %s -U %s -P %s" %(BMC_IP, BMC_username, BMC_password)
    ipmi_lan_cmds = collections.OrderedDict()
    ipmi_lan_cmds["bmc status"] = "%s raw 0x06 0x01" % IPMITOOL
    ipmi_lan_cmds["mc info"] = "%s mc info" % IPMITOOL
    ipmi_lan_cmds["sdr info"] = "%s sdr info" % IPMITOOL
    ipmi_lan_cmds["sol info"] = "%s sol info" % IPMITOOL
    ipmi_lan_cmds["lan info"] = "%s lan print" %IPMITOOL
    ipmi_local_cmds = collections.OrderedDict()
    ipmi_local_cmds["bmc status"] = "ipmitool raw 0x06 0x01"
    ipmi_local_cmds["mc info"] = "ipmitool mc info"
    ipmi_local_cmds["sdr info"] = "ipmitool sdr info"
    ipmi_local_cmds["lan info"] = "ipmitool lan print"
    white_list = [
        "Most recent Addition",
        "Most recent Erase",
    ]
    main()