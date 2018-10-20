#!/usr/bin/env python
# -*- coding:utf-8 -*-

import paramiko
import time
import re
import commands
__author__ = "Sam"

class CheckSSHSerivce(object):
    def __init__(self, ip, username, password, ssh_count=3, ssh_interval=3, ping_count=3, ping_interval=5, port=22):
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
            self.client.connect(self.ip, self.port, self.username, self.password)
        except Exception:
            return False
        else:
            self.close_ssh()
            return True

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

    def close_ssh(self):
        self.client.close()

    @staticmethod
    def ssh_run_cmd(cmd, ip, username, password, port=22):
        output, error, e = None, None, None
        paramiko.util.log_to_file("paramiko.log")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username=username, password=password, timeout=60)
            stdin, stdout, stderr = client.exec_command(cmd)
        except Exception as e:
            pass
        else:
            output = stdout.read().strip()
            error = stderr.read().strip()
        finally:
            client.close()
        if e:
            return 2, e
        if error:
            return 1, error
        return 0, output

if __name__ == '__main__':
    print CheckSSHSerivce.ssh_run_cmd("uptime", "10.2.33.145", "root", "111111")