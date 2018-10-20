#!/usr/bin/env python
# -*- coding:utf-8 -*-

import paramiko
import time
import re
import commands
import sys

class CheckSSHSerivce(object):
    def __init__(self, ip, username, password, ssh_count, ssh_interval, ping_count, ping_interval, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh_count = ssh_count
        self.ssh_interval = ssh_interval
        self.ping_count = ping_count
        self.ping_interval = ping_interval
        self.port = port

    def init_ssh(self):
        paramiko.util.log_to_file("/tmp/paramiko.log")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def check_ssh_work(self):
        try:
            self.client.connect(self.ip, self.port, self.username, self.password, timeout=60)
            return True
        except Exception:
            return False

    def loop_check_ssh_work(self):
        self.init_ssh()
        count = self.ssh_count
        while count > 0:
            if self.check_ssh_work():
                return True
            time.sleep(self.ssh_interval)
            count -= 1
        return False

    def ping(self):
        cmd = "ping -c 3 %s" %self.ip
        status, output = commands.getstatusoutput(cmd)
        if status == 0:
            recv = re.search(r'\d received', output, re.IGNORECASE)
            if recv:
                n = recv.group().split()[0]
                if int(n) > 0:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def loop_ping(self):
        count = self.ping_count
        while count > 0:
            if self.ping():
                return True
            time.sleep(self.ping_interval)
            count -= 1
        return False

if __name__ == '__main__':
    res = dict()
    res["ping"] = "fail"
    res["ssh"] = "fail"
    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    # ssh try time: 90s
    ssh_count = 6
    ssh_interval = 15
    # ping try time: 300s
    ping_count = 10
    ping_interval = 30
    check = CheckSSHSerivce(ip=ip, username=username, password=password, ssh_count=ssh_count, ssh_interval=ssh_interval, ping_count=ping_count,ping_interval=ping_interval)
    ping_flag = check.loop_ping()
    if ping_flag:
        res["ping"] = "pass"
        ssh_flag = check.loop_check_ssh_work()
        if ssh_flag:
            res["ssh"] = "pass"
    print res["ping"], res["ssh"]