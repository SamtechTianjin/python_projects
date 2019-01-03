# -*- coding:utf-8 -*-

from Log_init import env_init
env_init()      # To import django settings
import re
from Log import models
from sam_common import unicode_convert, run_cmd, Remote
from Log_args import *

# 根据数据库记录 恢复监控日志

def restore_monitor():
    # 从数据库获得记录的IP_Port
    print("Collect data from database...")
    flag_list = list()
    for log in models.Log.objects.all():
        flag = unicode_convert(log.filename).split(".log")[0]
        flag_list.append(flag)
    # 获得三地已经在监控的IP_Port
    monitor_list = list()
    check_cmd = "screen -ls"
    # Beijing
    print("[Beijing] Collect data from Log Server...")
    ret = run_cmd(check_cmd)
    for i in ret[-1].split("\n"):
        if not i: continue
        m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+.*Detached', i)
        if m:
            monitor_list.append(m.group().split()[0])
    # Tianjin
    print("[Tianjin] Collect data from Log Server...")
    ret = Remote.ssh_run_cmd(check_cmd,TJ_server_ip,TJ_username,TJ_password)
    for line in ret[-1].splitlines():
        if not line: continue
        m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+.*Detached', line)
        if m:
            monitor_list.append(m.group().split()[0])
    # Kunshan
    print("[Kunshan] Collect data from Log Server...")
    ret = Remote.ssh_run_cmd(check_cmd,KS_server_ip,KS_username,KS_password)
    for line in ret[-1].splitlines():
        if not line: continue
        m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+.*Detached', line)
        if m:
            monitor_list.append(m.group().split()[0])
    # print monitor_list
    # print flag_list
    for flag in flag_list:
        if flag not in monitor_list:
            ip, port = flag.split("_")
            if flag.startswith("10.0"):
                serial_add_script = os.path.join(script_path, "run.sh")
                monitor_cmd = "bash %s serial %s %s %s" %(serial_add_script, ip, port, log_path)
                ret = run_cmd(monitor_cmd)
            elif flag.startswith("10.2"):
                serial_add_script = os.path.join(TJ_script_path,"run.sh")
                monitor_cmd = "bash {0} serial {1} {2} {3}".format(serial_add_script,ip,port,TJ_log_path)
                ret = Remote.ssh_run_cmd(monitor_cmd,TJ_server_ip,TJ_username,TJ_password)
            elif flag.startswith("10.8"):
                serial_add_script = os.path.join(KS_script_path,"run.sh")
                monitor_cmd = "bash {0} serial {1} {2} {3}".format(serial_add_script,ip,port,KS_log_path)
                ret = Remote.ssh_run_cmd(monitor_cmd,KS_server_ip,KS_username,KS_password)
            else:
                ip,port = None,None
                print("[{0} {1}] Unknown IP address !!!")
            if ip and port:
                if ret[0] == 0:
                    print "[%s %s] Log collection start..." % (ip, port)
                else:
                    print "[%s %s] Log collection FAIL !" % (ip, port)



if __name__ == '__main__':
    restore_monitor()
