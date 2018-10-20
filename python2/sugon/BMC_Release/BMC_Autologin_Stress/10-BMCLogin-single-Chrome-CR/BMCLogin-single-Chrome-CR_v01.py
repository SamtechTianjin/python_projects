#---------------------------------------------------------------------------------
# Name:        BMCLogin.sh
# Purpose:     Many users access the BMC WEB Console with bmc cold reset concurrently
# Author:      Yanshunpeng
# Created:     06/06/2017
# Copyright:   (c) Administrator 2015
# Licence:     <your licence>
#-----------------------------------------------------------------------------------

# -*- coding:utf-8 -*-
import sys
import os
import time
import datetime
from selenium import webdriver
from optparse import OptionParser
import paramiko
import subprocess
import re

class PingFail(Exception):
    def __init__(self, err):
        super(PingFail, self).__init__(err)

class CheckBMCVersFail(Exception):
    def __init__(self, err):
        super(CheckBMCVersFail, self).__init__(err)

class LoginTimeout(Exception):
    def __init__(self, err):
        super(LoginTimeout, self).__init__(err)

class LoginFail(Exception):
    def __init__(self, err):
        super(LoginFail, self).__init__(err)

def del_file(dirname):
    l = os.listdir(dirname)
    for f in l:
        f = os.path.join(dirname, f)
        if os.path.isdir(f):
            del_file(f)
        else:
            os.remove(f)

def check(var):
    try:
        var
    except NameError:
        exist = False
    else:
        exist = True
    return exist

def run_command(cmd):
    status = 0
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = p.stdout.read().strip()
    error = p.stderr.read().strip()
    if error:
        print "[ERROR] %s" %error
        status = 1
    return status, output, error

def ping_test(ip, count=1):     # for windows
    p =subprocess.Popen("ping -n %s %s" %(str(count), str(ip)), shell=True, stdout=subprocess.PIPE)
    output = p.stdout.read().strip()
    ret = re.findall(r'%s.*ttl=\d+' %str(ip), output, re.IGNORECASE)
    if ret:
        lat = re.search(r'\d+[m]?s', ret[-1], re.IGNORECASE)
        return lat.group()
    return False

def SaveLog(filename, info, mode="a"):
    text_file = open(filename, mode)
    text_file.write(str(info))
    text_file.write("\n")
    text_file.close()

def calc_interval(startTime, endTime, flag="s"):
    interval = (endTime-startTime).days*86400+(endTime-startTime).total_seconds()
    if flag == "ms":
        return "%.1f" %(float(interval*1000))
    return "%.1f" %float(interval)

def SSHAutoLogin(ip,username,password,cmd,filename,port=22):
    # IPV4 and IPV6
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip,username=username,password=password,port=port)
        stdin,stdout,stderr=ssh.exec_command(cmd)
    except Exception,e:
        outstring = "[Exception - SSH]\n{0}".format(str(e))
        SaveLog(filename, outstring)
        print outstring
        ssh.close()
    else:
        output = stdout.read().strip()
        ssh.close()
        return output

def CheckLighttpd(ip,username,password,filename):
    cmd = "ps -ef | grep -i lighttpd | grep -v grep"
    ret = SSHAutoLogin(ip,username,password,cmd,filename)
    return ret

def GetNowTime():
    return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))

def find_until_timeout(cmd, timeout):
    startTime = datetime.datetime.now()
    interval = 0
    ret = ""
    while float(interval) <= timeout:
        try:
            ret = eval(cmd)       # return value for cmd
        except Exception, e:
            pass
        finally:
            tmpTime = datetime.datetime.now()
            interval = calc_interval(startTime, tmpTime)
        if ret:
            time.sleep(5)
            break
    else:
        interval = timeout
    return ret, interval

def login(ip,username,password,count,flag):
    flag = flag.strip().lower()
    photo_name = "%s_%s.png" %(flag, str(count))
    photo_dir = os.path.join(screenshot_dir, photo_name)
    global driver
    try:
        if flag == "chrome":
            driver = webdriver.Chrome(chrome_driver)      # chrome browser
        elif flag == "ie":
            driver = webdriver.Ie(ie_driver)              # IE browser
        elif flag == "firefox":
            driver = webdriver.Firefox()                  # firefox browser which needs "geckodriver.exe"
        else:
            sys.exit(1)
        baseurl = "http://%s" %ip                         # bmc web ip
        ret = ping_test(ip, count=3)
        current = GetNowTime()
        if not ret:
            raise PingFail("Current time is : %s, %s ping fail !" % (current, ip))
        output = "Current time is : %s, %s ping OK ." %(current, ip)
        SaveLog(log_path, output)
        print output
        ret = check_mc_info(ip, username, password)
        current = GetNowTime()
        if not ret:
            raise CheckBMCVersFail("Current time is : %s, get BMC version fail !" %current)
        output = "Current time is : %s, BMC version is %s." %(current, ret)
        SaveLog(log_path, output)
        print output
        driver.get(baseurl)
        driver.implicitly_wait(5)
        driver.maximize_window()
        driver.find_element_by_id("userid").clear()
        driver.find_element_by_id("userid").send_keys(username)     # input username
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys(password)   # input password
        driver.find_element_by_id("btn-login").click()              # click login
        # For BMC code update
        alert_time = 0
        if opts.version.lower() == "new":
            startTime = datetime.datetime.now()
            cmd = 'driver.switch_to_alert()'
            ret = find_until_timeout(cmd, 20)
            if ret[0]:
                ret[0].accept()
                endTime = datetime.datetime.now()
                alert_time = calc_interval(startTime, endTime)
            else:
                output = "Don't find prompt box, timeout : %ss." %str(ret[1])
                SaveLog(log_path, output)
                print output
                driver.quit()
                sys.exit(1)
        # Try login ...   less than timeout
        # cmd = 'driver.find_element_by_id("serInfo_prodectname").text.encode(encoding="utf-8").strip()'
        cmd = 'driver.find_element_by_id("serInfo_GUID")'
        ret, interval = find_until_timeout(cmd, 20)     # timeout: 20s
        if ret:
            interval = float(interval) + float(alert_time)
            current = GetNowTime()
            output = "Current time is : %s, Count %s : [%s] Login finish." % (current, str(count), flag)
            SaveLog(log_path, output)
            print output
            SaveLog(loginTime_path, "[%s] Count %s : %ss" % (flag, str(count), str(interval)))  # save login time
            print "[%s] Login time : %ss" % (flag, str(interval))
            cmd = 'driver.find_element_by_id("lan_Webonline").text.encode(encoding="utf-8").strip()'
            userNum = int(find_until_timeout(cmd, 10)[0])       # timeout: 20s
            current = GetNowTime()
            if not userNum:
                raise LoginFail("Current time is : %s, [%s] get user number fail !" % (current, flag))
            else:
                if int(userNum) != 1:
                    output = "Current time is : %s, [%s] Check user fail , current user number is %s not 1." % (
                    current, flag, str(userNum))
                else:
                    output = "Current time is : %s, [%s] Check user OK, current user number : 1." % (current, flag)
                SaveLog(log_path, output)
                print output
            # check event-log && return dashboard
            time.sleep(2)
            links = driver.find_elements_by_tag_name("a")
            event_log = []
            dashboard = []
            for link in links:
                ret = link.get_attribute("href")
                if isinstance(ret, unicode):
                    ret = ret.encode(encoding="utf-8")
                    d = re.search(r'.*dashboard$', ret)
                    if d:
                        dashboard.append(link)
                        continue
                    e = re.search(r'.*logs/event-log$', ret)
                    if e:
                        event_log.append(link)
            event_log[-1].click()  # check event log
            cmd = 'driver.find_element_by_id("lr_event_log")'
            ret = find_until_timeout(cmd, 10)[0]
            if ret:
                time.sleep(5)       # To show event_log
                dashboard[-1].click()
                time.sleep(1)
                # cmd = 'driver.find_element_by_id("serInfo_prodectname").text.encode(encoding="utf-8").strip()'
                cmd = 'driver.find_element_by_id("serInfo_GUID")'
                ret = find_until_timeout(cmd, 10)[0]
                if ret:
                    # logout
                    current = GetNowTime()
                    output = "Current time is : %s, Count %s : [%s] Login successful, begin logout ..." % (
                    current, str(count), flag)
                    SaveLog(log_path, output)
                    print output
                    time.sleep(3)
                    driver.find_element_by_class_name("username").click()
                    time.sleep(1)
                    driver.find_element_by_class_name("pull-right").click()
                    time.sleep(1)
                    driver.switch_to_alert().accept()
                    time.sleep(3)  # wait logout
                else:
                    current = GetNowTime()
                    raise LoginFail("Current time is : %s, [%s] return dashboard fail !" % (current, flag))
            else:
                current = GetNowTime()
                raise LoginFail("Current time is : %s, [%s] check event log fail !" % (current, flag))
        else:
            driver.get_screenshot_as_file(photo_dir)
            SaveLog(loginTime_path, "[%s] Count %s : failed" % (flag, str(count)))
            current = GetNowTime()
            raise LoginTimeout("Current time is : %s, Count %s : [%s] Login timeout [%ss]" %(current, str(count), flag, interval))
    except (PingFail, CheckBMCVersFail) as e:
        SaveLog(log_path, str(e))
        print e
        sys.exit(1)
    except (LoginTimeout, LoginFail) as e:
        SaveLog(log_path, str(e))
        print e
        print "Try ping %s ..." %ip
        timeout = 30
        t = 0
        ping_start = datetime.datetime.now()
        while float(t) <= timeout:
            ret = ping_test(ip)
            ping_tmp = datetime.datetime.now()
            t = calc_interval(ping_start, ping_tmp, flag="ms")     # return string not float
            if ret:
                print "[%s] ping time : %sms" %(ip, t)
                break
        else:
            current = GetNowTime()
            output = "Current time is : %s, %s ping fail exceeds %ss, exit ..." %(current, ip, str(timeout))
            SaveLog(log_path, output)
            print output
            driver.quit()   # close browser
            sys.exit(1)
        ret = CheckLighttpd(ip, username, password, log_path)
        if not ret:
            output = "Service lighttpd fail, exit ..."
            SaveLog(log_path, output)
            print output
            driver.quit()  # close browser
            sys.exit(2)
        else:
            output = "Service lighttpd OK, next loop ..."
            SaveLog(log_path, output)
            print output
    except Exception, e:
        print e
    finally:
        driver.quit()   # close browser

def check_power_status(flag, ip, username="admin", password="admin", interval=10, counts=3):
    i = 0
    powerstatus_cmd = "%s -I lanplus -H %s -U %s -P %s chassis power status" % (ipmitool, ip, username, password)
    cmd = "%s -I lanplus -H %s -U %s -P %s chassis power %s" % (ipmitool, ip, username, password, flag)
    ret = run_command(cmd)
    if ret[0] != 0:
        sys.exit(1)
    time.sleep(interval)
    while i < counts:
        ret = run_command(powerstatus_cmd)
        if ret[0] != 0:
            sys.exit(1)
        powerStatus = ret[1].strip().split()[-1].strip()
        if powerStatus == flag:
            current = GetNowTime()
            output = "Current time is : %s, Power %s success." %(current, flag)
            SaveLog(log_path, output)
            print output
            break
        else:
            ret = run_command(cmd)
            if ret[0] != 0:
                sys.exit(1)
            time.sleep(interval)
            i += 1
    else:
        current = GetNowTime()
        output = "Current time is : %s, Power %s failed more than %s times, exit ..." %(current, flag, str(counts))
        SaveLog(log_path, output)
        print output
        sys.exit(1)

def check_mc_info(ip, username, password):
    vers_info = ""
    cmd = "%s -I lanplus -H %s -U %s -P %s mc info" % (ipmitool, ip, username, password)
    ret = os.popen(cmd).readlines()
    for line in ret:
        if not line: continue
        m = re.search(r'Firmware Revision.*', line, re.IGNORECASE)
        if m:
            vers_info = m.group().split(":")[-1].strip()
    return vers_info

def BMCPOO(ip, username="admin", password="admin", interval=30):
    current = GetNowTime()
    output = "Current time is : %s, BMC begin to Power off ..." %current
    SaveLog(log_path, output)
    print output
    check_power_status("off", ip, username, password)
    time.sleep(3)
    check_power_status("on", ip, username, password)
    time.sleep(interval)

def BMCColdReset(ip, username="admin", password="admin", interval=300):
    current = GetNowTime()
    output = "Current time is : %s, BMC begin to cold reset ..." %current
    SaveLog(log_path, output)
    print output
    cmd = "%s -I lanplus -H %s -U %s -P %s mc reset cold" %(ipmitool, ip, username, password)
    ret = run_command(cmd)
    if ret[0] != 0:
        sys.exit(1)
    time.sleep(interval)

def main(host, username, password, count):
    # Pretest
    output = " Pretest ".center(50, "#")
    SaveLog(log_path, output)
    print output
    print "The login time is :", time.strftime('%Y-%m-%d %H:%M:%S')
    login(host, username, password, 0, flag="chrome")
    # login(host, username, password, i, flag="ie")
    # login(host, username, password, i, flag="firefox")
    count += 1
    for i in range(1, count):
        SaveLog(log_path, "")
        time.sleep(1)
        print ""
        loopNum = " Loop %s " %str(i)
        output = loopNum.center(50, "#")
        SaveLog(log_path, output)
        print output
        print "The login time is :", time.strftime('%Y-%m-%d %H:%M:%S')
        # BMCPOO(host, username, password)            # Chassis power off/on via IPMI
        BMCColdReset(host, username, password)      # BMC cold reset via IPMI
        login(host, username, password, i, flag="chrome")
        # login(host, username, password, i, flag="ie")
        # login(host, username, password, i, flag="firefox")
        i+=1

def parse_time(filename):
    res = dict()
    f = open(filename, "r")
    data = f.readlines()
    f.close()
    chrome_list, ie_list, firefox_list = [], [], []
    l = {"chrome": chrome_list,
         "ie": ie_list,
         "firefox": firefox_list}
    for line in data:
        if "Count 0" in line: continue
        if "failed" in line: continue
        if not line: continue
        t = line.split(":")[-1].strip().split("s")[0]
        m = re.match(r"\[\w+\]", line, re.IGNORECASE)
        browser = m.group().strip("[]")
        for k,v in l.items():
            if k == browser:
                v.append(float(t))
                break
    for k,v in l.items():
        if not v: continue
        if not res.has_key(k): res[k] = dict()
        res[k]["min"] = min(v)
        res[k]["max"] = max(v)
    return res

def run(flag, ip, username="admin", password="admin"):
    if flag == "before":
        sel_cmd = "%s -I lanplus -H %s -U %s -P %s sel clear" %(ipmitool, ip, username, password)
    elif flag == "after":
        sel_cmd = "%s -I lanplus -H %s -U %s -P %s sel elist" %(ipmitool, ip, username, password)
    else:
        sel_cmd = ""
    bmc_ret = os.popen(sel_cmd).read().strip()
    return bmc_ret

if __name__ == '__main__':
    # get args
    parser = OptionParser()
    parser.add_option('-H','--host',dest='host',type='string',help='IP eg: 10.0.0.10')
    parser.add_option('-U','--username',dest='username',type='string',help='username for login')
    parser.add_option('-P','--password',dest='password',type='string',help='password for login',)
    parser.add_option('-C','--count',dest="count",type="int",help='test count for login, default : 1000',default=1000)
    parser.add_option('-V','--version',dest="version",type="string",help='BMC code [old/new], default : old',default="old")
    opts,args = parser.parse_args()
    current_path = os.path.dirname(os.path.abspath(__file__))
    usage = os.popen("python %s --help" %(sys.argv[0])).read().strip()
    if not opts.host or not opts.username or not opts.password:
        print "\n%s" %usage
        sys.exit(1)
    # tools
    tools_dir = os.path.join(current_path, "tools")
    chrome_driver = "chromedriver.exe"
    ie_driver = "IEDriverServer.exe"
    ipmitool = os.path.join(tools_dir, "ipmitool.exe")
    # log file
    dirname = "log_%s" %(opts.host)
    log_dir = os.path.join(current_path, dirname)
    log_path = os.path.join(log_dir, "BMC_Autologin.log")
    loginTime_path = os.path.join(log_dir, "Login_Time.log")
    dirname = "screenshots_%s" %(opts.host)
    screenshot_dir = os.path.join(current_path, dirname)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    else:
        del_file(log_dir)
    if not os.path.exists(screenshot_dir):
        os.makedirs(screenshot_dir)
    else:
        del_file(screenshot_dir)
    # main test
    run("before", opts.host, opts.username, opts.password)              # clear SEL
    current=GetNowTime()
    output = 'Current time is :' + str(current) + ", " + "Begin to test BMC autologin ..."
    SaveLog(log_path, output, mode="w")
    main(opts.host, opts.username, opts.password, opts.count)
    bmc_ret = run("after", opts.host, opts.username, opts.password)     # collect SEL
    output = "\n[ BMC SEL info ]\n   %s" %bmc_ret
    SaveLog(log_path, output)
    print output
    output = "\n[ Login Time ]\n"
    for k,v in parse_time(loginTime_path).items():
        output += "%s:\n" %k
        output += "  min: %ss\n" %v["min"]
        output += "  max: %ss\n" %v["max"]
    SaveLog(log_path, output)
    print output