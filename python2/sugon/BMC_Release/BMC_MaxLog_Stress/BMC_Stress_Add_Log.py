# -*- coding:utf-8 -*-

import os
import sys
import shutil
import argparse
import json
import re
import datetime
from multiprocessing import Process
from Test_common import Remote, AutoTest

"""
audit日志: /conf/log/audit.log(350条左右)
SEL日志: 3639条 or 65532 bytes
/var/log/*:
messages,dmesg (日志超过50K将会产生messages.1和dmesg.1,然后日志清空)
btmp (日志超过50K不清空)
others (日志超过50K直接清空)
"""


SCRIPT = os.path.abspath(__file__)
CUR_PATH = os.path.dirname(SCRIPT)

class LoginFail(Exception):
    def __init__(self, error):
        super(LoginFail, self).__init__(error)

class LogoutFail(Exception):
    def __init__(self, error):
        super(LogoutFail, self).__init__(error)

class BMCStress(AutoTest):

    def __init__(self, ip, case="BMC_Stress", username="sysadmin", password="superuser", timeout=60, directory="/var/log", user="admin", passwd="admin"):
        super(BMCStress, self).__init__()
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.directory = directory
        self.user = user
        self.passwd = passwd
        self.backup_log = os.path.join(CUR_PATH, "Backup_log")
        self.log_dir = os.path.join(CUR_PATH, "Log_%s"%BMCStress.get_currnet_time(timestamp_format="%Y%m%d%H%M%S"))
        self.log = os.path.join(self.log_dir, "%s.log"%case)
        self.init_log()

    def init_log(self):
        if not os.path.exists(self.backup_log):
            os.makedirs(self.backup_log)
        os.chdir(CUR_PATH)
        for l in os.listdir("."):
            if l.startswith("Log_"):
                shutil.move(l, os.path.join(self.backup_log, l))
        os.makedirs(self.log_dir)
        BMCStress.save_data(self.log, "", flag="w", timestamp=False)

    def add_sel(self):
        add_cmd = "ipmitool -I lanplus -U {0} -P {1} -H {2} raw 0x0a 0x44 0x00 0x00 0x02 0x00 0x00 0x00 0x00 0x20 0x00 0x04 0x01 0x13 0x01 0x57 0x3f 0x33".format(self.user,self.passwd,self.ip)
        check_num_cmd = "ipmitool -I lanplus -U {0} -P {1} -H {2} sel elist | wc -l".format(self.user,self.passwd,self.ip)
        while True:
            ret = self.run_cmd(check_num_cmd)
            if ret[0] == 0:
                num = int(ret[1])
                if num < SEL_MAX:
                    ret = self.run_cmd(add_cmd)
                    if ret[0] != 0:
                        message = "Added SEL log FAIL !\n{0}".format(ret[1])
                        self.show_message(message,flag="red")
                        return False
                else:
                    message = "The number of SEL arrived {0}.".format(num)
                    break
            else:
                message = "Checked SEL number FAIL !\n{0}".format(ret[-1])
                self.show_message(message,flag="red")
                return False
        return True

    def add_audit(self):
        audit_num = int(AUDIT_MAX*0.9)
        filename = "/conf/log/audit.log"
        cmd = "echo 'Added audit log' >> {1}; " \
              "while [ `cat {1} | wc -l` -lt {0} ]; do " \
              "temp=`head -n 1 {1}`; " \
              "echo $temp >> {1}; " \
              "done".format(audit_num,filename)
        status,output = Remote.ssh_run_cmd(cmd,self.ip,self.username,self.password)
        if status == 0:
            message = "The number of audit log arrived {0}.".format(AUDIT_MAX)
        else:
            message = "Added audit log FAIL !\n{0}".format(output)
            self.show_message(message,flag="red")
            return False
        return True

    def add_log(self):
        log_size = int(LOG_MAX*0.95)
        cmd = "cd %s; " \
              "ls -l | sed -n '2,$'p > temp.txt; " \
              'while read line;do ' \
              "size=`echo $line | awk '{print $5}'`; " \
              "filename=`echo $line | awk '{print $NF}'`; " \
              'if [ "$size" -lt %s ];then ' \
              "dd if=/dev/zero of=$filename bs=%s count=1; " \
              "fi; " \
              "done < temp.txt;" % (self.directory, log_size, log_size)
        status, output = Remote.ssh_run_cmd(cmd, self.ip, self.username, self.password)
        if status != 2:
            message = "[/var/log/] All logs arrived {0} bytes.".format(log_size)
        else:
            message = "[/var/log/] Added log FAIL !\n{0}".format(output)
            self.show_message(message,flag="red")
            return False
        return True

    """
    def get_total_size(self):
        res_dict = collections.OrderedDict()
        log_dict = dict()
        total = 0
        max_size = 0
        max_size_log = ""
        cmd = "ls -l %s" %self.directory
        status,output = Remote.ssh_run_cmd(cmd, self.ip, self.username, self.password, timeout=self.timeout)
        message = "command: %s\nreturn code: %s\n%s" %(cmd, status, output)
        BMCStress.save_data(self.log, message)
        if status == 0:
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("total"):
                    total = line.split()[-1].strip()
                else:
                    tmp_list = line.split()
                    log_size = int(tmp_list[4])
                    log_name = tmp_list[-1].strip()
                    log_dict[log_name] = log_size
            temp = sorted(log_dict.items(),key=lambda x:int(x[1]))
            res_dict["total"] = total
            res_dict["max_size_log"],res_dict["max_size"] = temp[-1]
            res_dict["min_size_log"],res_dict["min_size"] = temp[0]
            res_dict["log_list"] = log_dict.keys()
        else:
            return 1, output
        return 0, res_dict

    def add_log_size(self, data):
        cmd = "cd %s;" %self.directory
        # if int(data["total"]) <= int(TOTAL_SIZE/2):
        #     for f in data["log_list"]:
        #         if f == data["max_size_log"]: continue
        #         cmd += "cat {0} >> {1};".format(data["max_size_log"],f)
        # else:
        #     cmd += "cat {0} >> {1};".format(data["max_size_log"],data["min_size_log"])
        cmd += "cat {0} >> {1};".format(data["max_size_log"], data["min_size_log"])
        status, output = Remote.ssh_run_cmd(cmd, self.ip, self.username, self.password, timeout=self.timeout)
        message = "command: %s\nreturn code: %s\n%s" %(cmd, status, output)
        BMCStress.save_data(self.log, message)
        return status, output
    """

    def check_status(self):
        username = self.user
        password = self.passwd
        ipmitool = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(self.ip, username, password)
        # 1. To ping BMC IP
        ping_ret = Remote.ping_test(self.ip)
        if ping_ret:
            message = "[{0}] BMC IP ping OK !".format(self.ip)
            BMCStress.save_data(self.log, message)
            # 2. Run ipmi command
            ipmi_fail = False
            ipmi_cmds = {
                "version" : "{0} raw 0x06 0x01".format(ipmitool),
                "mc info" : "{0} mc info".format(ipmitool),
                "sdr info": "{0} sdr info".format(ipmitool),
                "sol info": "{0} sol info".format(ipmitool)
            }
            for name,ipmi_cmd in ipmi_cmds.iteritems():
                status,output = BMCStress.run_cmd(ipmi_cmd)
                if status == 0:
                    message = "Check BMC {0} OK !".format(name)
                else:
                    message = "Check BMC {0} FAIL !\n{1}".format(name, output)
                    ipmi_fail = True
                BMCStress.save_data(self.log, message)
                if ipmi_fail:
                    BMCStress.show_message(message, flag="red")
                    return False
            # 3. Check Web login
            login_fail = False
            csrf_token = None
            logout_fail = False
            try:
                login_cmd = "curl -X POST -d \"username={0}&password={1}\" \"http://{2}/api/session\" -c ./cookie 2> /dev/null".format(username, password, self.ip)
                status,output = BMCStress.run_cmd(login_cmd)
                if status == 0:
                    ret_dict = json.loads(output.strip())
                    if ret_dict.get("ok") == 0:
                        csrf_token = ret_dict.get("CSRFToken")
                    else:
                        raise LoginFail(ret_dict)
                else:
                    raise LoginFail("[curl] The return code is not 0 !")
            except Exception as e:
                login_fail = True
                message = "Login web FAIL !\n{0}".format(e)
            else:
                message = "Login web OK !"
            finally:
                BMCStress.save_data(self.log, message)
                if login_fail:
                    BMCStress.show_message(message, flag="red")
                    return False
                else:
                    if csrf_token:
                        try:
                            logout_cmd = 'curl -X DELETE -H "X-CSRFTOKEN:{0}" "http://{1}/api/session" -b ./cookie 2> /dev/null'.format(
                                csrf_token, self.ip)
                            status,output = BMCStress.run_cmd(logout_cmd)
                            if status == 0:
                                ret_dict = json.loads(output.strip())
                                if ret_dict.get("ok") == 0:
                                    message = "Logout web OK !"
                                else:
                                    raise LogoutFail(ret_dict)
                            else:
                                raise LogoutFail("[curl] The return code is not 0 !")
                        except Exception as e:
                            logout_fail = True
                            message = "Logout web FAIL !\n{0}".format(e)
                        finally:
                            BMCStress.save_data(self.log, message)
                            if logout_fail:
                                BMCStress.show_message(message, flag="red")
                                return False
            # 4. Check SEL
            warn_list = ["warn", "error", "fatal", "fail"]  # 警告关键词
            sel_fail = False
            fail_list = list()
            cmd = "{0} sel elist".format(ipmitool)
            status,output = BMCStress.run_cmd(cmd)
            if status == 0:
                regex = re.compile(r'{0}'.format("|".join(warn_list)), re.IGNORECASE)
                for line in output.splitlines():
                    if not line: continue
                    m = regex.search(line)
                    if m:
                        sel_fail = True
                        fail_list.append(line)
                if sel_fail:
                    message = "Check SEL FAIL !\n{0}".format(fail_list)
                else:
                    message = "Check SEL PASS !"
            else:
                sel_fail = True
                message = "[ipmitool] Collect SEL FAIL !\n{0}".format(output)
            BMCStress.save_data(self.log, message)
            if sel_fail:
                BMCStress.show_message(message, flag="red")
                return False
        else:
            message = "[{0}] BMC IP ping FAIL !".format(self.ip)
            BMCStress.save_data(self.log, message)
            BMCStress.show_message(message, flag="red")
            return False
        return True

    @classmethod
    def main(cls):
        bmc = cls(BMC_IP, username=USERNAME, password=PASSWORD, user=USER, passwd=PASSWD)
        start_time = datetime.datetime.now()
        while AutoTest.calc_time_interval(start_time,datetime.datetime.now()) < TIME:
            """
            while True:
                status, data = bmc.get_total_size()
                if status == 0:
                    message = "total value: %s" % data["total"]
                    if TOTAL_SIZE-int(data["total"]) <= int(data["max_size"])/1000:
                        BMCStress.show_message(message, flag="red")
                        BMCStress.save_data(bmc.log, message)
                        break
                    BMCStress.show_message(message)
                    ret = bmc.add_log_size(data)
                    if ret[0] != 0:
                        message = "Add log size FAIL !\n%s" % (ret[-1])
                        BMCStress.show_message(message, flag="red")
                        BMCStress.save_data(bmc.log, message)
                        return False
                    time.sleep(3)
                else:
                    message = "Collect log data FAIL !"
                    BMCStress.show_message(message, flag="red")
                    BMCStress.save_data(bmc.log, message)
                    return False
            """
            processes = list()
            for func in [bmc.add_audit,bmc.add_sel,bmc.add_log]:
                p = Process(target=func)
                processes.append(p)
                p.start()
            for p in processes:
                p.join()
            if CHECK:
                check_bmc_pass = bmc.check_status()
                if check_bmc_pass:
                    message = "Check BMC status PASS !"
                    BMCStress.save_data(bmc.log, message)
                    BMCStress.show_message(message, flag="green")
                else:
                    break

def get_args():
    parser = argparse.ArgumentParser(prog=None, usage="", description="The script will fill BMC log to run BMC stress test.")
    parser.add_argument("-V","--version",dest="version",action="version",version="BMCMaxLog V1.0",help="show program's version number and exit")
    parser.add_argument("-C","--check",dest="check",action="store_true",default=False,help="Check BMC status in every loop")
    parser.add_argument("-B","--bmc",metavar="bmcip",dest="bmcip",type=str,action="store",default="",help="BMC IP address")
    parser.add_argument("-S","--size",metavar="maxsize",dest="maxsize",type=int,action="store",default=50000,help="BMC log maxinum, unit: Byte, default: 50000")
    parser.add_argument("-A","--audit",metavar="maxnum",dest="audit",type=int,action="store",default=350,help="Maximun number of audit logs, default: 350")
    parser.add_argument("--sel",metavar="maxnum",dest="sel",type=int,action="store",default=3639,help="Maximun number of SEL, default: 3639")
    parser.add_argument("-U","--username",metavar="username",dest="username",type=str,default="sysadmin",action="store",help="BMC administrator username, default: sysadmin")
    parser.add_argument("-P","--password",metavar="password",dest="password",type=str,default="superuser",action="store",help="BMC administrator password, default: superuser")
    parser.add_argument("--user",metavar="user",dest="user",type=str,default="admin",action="store",help="BMC username, default: admin")
    parser.add_argument("--passwd",metavar="passwd",dest="passwd",type=str,default="admin",action="store",help="BMC password, default: admin")
    parser.add_argument("-T","--time",metavar="time",dest="time",type=int,default=43200,action="store",help="BMC stress time, default: 43200")
    args = vars(parser.parse_args())
    return args


if __name__ == '__main__':
    args = get_args()
    USERNAME,PASSWORD,USER,PASSWD,BMC_IP,TIME,LOG_MAX,SEL_MAX,AUDIT_MAX,CHECK = \
        [args[item] for item in ["username","password","user","passwd","bmcip","time","maxsize","sel","audit","check"]]
    if not BMC_IP:
        print "\033[1;31m Please input BMC IP !\033[0m"
        sys.exit(1)
    BMCStress.main()
