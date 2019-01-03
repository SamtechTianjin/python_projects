# -*- coding:utf-8 -*-

import os,sys
import subprocess
import signal
import time
import re
import commands
Current_Path = os.path.abspath(os.path.dirname(__file__))
path = os.path.abspath(os.path.join(Current_Path,os.path.pardir))
sys.path.append(path)


try:
    # Beijing
    from Log_args import script_path,log_path
    # Tianjin
    from Log_args import TJ_username,TJ_password,TJ_server_ip,TJ_script_path,TJ_log_path
    # Kunshan
    from Log_args import KS_username,KS_password,KS_server_ip,KS_script_path,KS_log_path
    from sam_common import Remote
except:
    print("It's not Beijing LogServer !!!")
    sys.exit(1)

"""
通过tcpdump监控${Monitor_Time}秒 处理数据一次
"""
Monitor_Time = 300
Interval = 5
Monitor_IP = "10.0.21.63"
Monitor_Port = "9999"
Temp_File = "/var/www/html/Platform/Log/temp/Serial_Log.txt"



def Get_NIC_Port_Name():
    name = None
    cmd = "ifconfig -a | grep -B 1 %s | head -n 1 | awk -F: '{print $1}'" %(Monitor_IP)
    child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = child.communicate()
    if output.strip():
        name = output.strip()
    return name

def Get_Monitor_Command():
    name = Get_NIC_Port_Name()
    if name:
        cmd = "tcpdump -i {0} udp port {1} -e &> {2}".format(name,Monitor_Port,Temp_File)
        if os.getuid() != 0:
            cmd = "sudo {0}".format(cmd)
        return cmd

def Kill_Process(name="tcpdump",retry_count=5):
    cmd = "killall {0}".format(name)
    if os.getuid() != 0:
        cmd = "sudo {0}".format(cmd)
    while retry_count > 0:
        ret = os.popen("ps -ef | grep {0} | grep -v grep".format(name))
        if ret.read().strip():
            os.system(cmd)
        else:
            break
        time.sleep(1)
        retry_count -= 1

def Parse_File_Data():
    unique_list = []
    with open(Temp_File,"r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("tcpdump"): continue
            elif line.startswith("listening"): continue
            elif not line: continue
            if re.match(r'(\d{2}:){2}\d{2}',line):
                temp_list = line.split()
                ip_port = temp_list[13]
                mac_address = temp_list[1]
                ip = re.match(r'(\d+\.){3}\d+',ip_port).group()
                port = ip_port.split(".")[-1]
                temp = {
                    "MAC": mac_address,
                    "IP": ip,
                    "PORT": port
                }
                if temp in unique_list:
                    continue
                unique_list.append(temp)
    return unique_list

def Get_Filename_Via_Screen():
    # 返回使用screen监控的信息
    filenames = []
    cmd = "screen -ls"
    # Beijing
    print("[Beijing] Collect data from Log Server...")
    child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = child.communicate()
    try:
        for line in output.splitlines():
            if not line: continue
            if line.startswith("There are screens on"): continue
            if re.search(r'\d+ Sockets in', line): continue
            m = re.search(r'(\d+\.){3}\d+_\d+', line)
            if m:
                filename = m.group()
                filenames.append(filename)
        # Tianjin
        print("[Tianjin] Collect data from Log Server...")
        ret = Remote.ssh_run_cmd(cmd,TJ_server_ip,TJ_username,TJ_password)
        for line in ret[-1].splitlines():
            if not line: continue
            m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+', line)
            if m:
                filename = m.group()
                filenames.append(filename)
        # Kunshan
        print("[Kunshan] Collect data from Log Server...")
        ret = Remote.ssh_run_cmd(cmd,KS_server_ip,KS_username,KS_password)
        for line in ret[-1].splitlines():
            if not line: continue
            m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+', line)
            if m:
                filename = m.group()
                filenames.append(filename)
    except Exception as e:
        text = "[Exception - 'screen -ls']\n{0}".format(e)
        print(text)
    return filenames

def Update_Monitor():
    collect_list = Parse_File_Data()
    for temp in collect_list:
        ip,port = [temp.get(item,None) for item in ["IP","PORT"]]
        if ip and port:
            filename = "_".join([ip,port])
            for i in range(3):  # 检测3次 如果未监控 则开始收集日志
                monitor_list = Get_Filename_Via_Screen()
                if filename in monitor_list:
                    break
                time.sleep(3)
            else:
                # Beijing
                if ip.startswith("10.0"):
                    cmd = "bash {0} serial {1} {2} {3}".format(script_path,ip,port,log_path)
                    ret = commands.getstatusoutput(cmd)
                # Tianjin
                elif ip.startswith("10.2"):
                    serial_add_script = os.path.join(TJ_script_path, "run.sh")
                    monitor_cmd = "bash {0} serial {1} {2} {3}".format(serial_add_script, ip, port, TJ_log_path)
                    ret = Remote.ssh_run_cmd(monitor_cmd, TJ_server_ip, TJ_username, TJ_password)
                # Kunshan
                elif ip.startswith("10.8"):
                    serial_add_script = os.path.join(KS_script_path, "run.sh")
                    monitor_cmd = "bash {0} serial {1} {2} {3}".format(serial_add_script, ip, port, KS_log_path)
                    ret = Remote.ssh_run_cmd(monitor_cmd, KS_server_ip, KS_username, KS_password)
                else:
                    ip,port,ret = None,None,None
                    print("[{0} {1}] Unknown IP address !!!")
                if ip and port:
                    if ret[0] == 0:
                        print "[%s %s] Log collection start..." % (ip, port)
                    else:
                        print "\033[1;31m[%s %s] Log collection FAIL !\033[0m" % (ip, port)


if __name__ == '__main__':
    """
    确定是否为北京机台 自动收集操作只执行在北京机台
    """
    if Get_NIC_Port_Name():
        while True:
            cmd = Get_Monitor_Command()
            if cmd:
                child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                child_pid = child.pid
                time.sleep(Monitor_Time)
                os.kill(child_pid,signal.SIGKILL)
                Kill_Process(name="tcpdump")
                time.sleep(1)
                Update_Monitor()
                time.sleep(Interval)
            else:
                message = "Unknown monitor command !!!"
                print(message)
                break
    else:
        message = "It's not Beijing LogServer !!!"
        print(message)
