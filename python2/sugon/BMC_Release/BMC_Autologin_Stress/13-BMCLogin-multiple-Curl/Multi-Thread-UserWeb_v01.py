#!/usr/bin/python
# coding:utf-8
#===============Sugon test BMC 20 user login Web ====================================================
# Sugon Modified version v1.0
# Description:
# USAGE: 
# AUTHOR: Yanshupeng
# CREATED: 11/08/2017
#=====================================================================================================
import sys
import datetime
import os
import commands
import json
import time
import re
import threading
from optparse import OptionParser
import subprocess
import paramiko

class PingFail(Exception):
    def __init__(self, err):
        super(PingFail, self).__init__(err)

class LoginFail(Exception):
    def __init__(self, err):
        super(LoginFail, self).__init__(err)

class LogoutFail(Exception):
    def __init__(self, err):
        super(LogoutFail, self).__init__(err)

def del_file(dirname):
    l = os.listdir(dirname)
    for f in l:
        f = os.path.join(dirname, f)
        if os.path.isdir(f):
            del_file(f)
        else:
            os.remove(f)

def GetNowTime():
    return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))

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

def ping_test(ip, count=3):     # for linux
    p =subprocess.Popen("ping -c %s %s" %(str(count), str(ip)), shell=True, stdout=subprocess.PIPE)
    output = p.stdout.read().strip()
    ret = re.findall(r'%s.*ttl=\d+.*time=.*' %str(ip), output, re.IGNORECASE)
    if ret:
        lat = re.search(r'time=.*s', ret[-1], re.IGNORECASE)
        return lat.group().split("time=")[-1]
    SaveLog(log_path, output)
    return False

def SSHAutoLogin(ip,username,password,cmd,filename,port=22):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip,username=username,password=password,port=port)
        stdin,stdout,stderr=ssh.exec_command(cmd)
        output = stdout.read().strip()
    except Exception,e:
        outstring = "[Exception - SSH]\n%s" %str(e)
        SaveLog(filename, outstring)
        print outstring
    finally:
        ssh.close()
        try:
            output
        except NameError:
            pass
        else:
            return output

def CheckLighttpd(ip,username,password,filename):
    cmd = "ps -ef | grep -i lighttpd | grep -v grep"
    ret = SSHAutoLogin(ip,username,password,cmd,filename)
    return ret

def doLogin(i):
    restapi='/api/session'
    curlcmd='curl -X POST -d \"username=' + username + '&password=' + password + '\" ' + '\"http://' + bmcip + restapi + '\" -c ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    print result  # debug
    if result[0] == 0:
        output=json.loads(result[1])
        global token        # change global token
        if output.has_key('ok'):
            token[i]=output['CSRFToken']
            status=output['ok']
        else:
            status=1
    else:
        outstring = 'Thread is : %s, login FAIL' % str(i)
        raise LoginFail(outstring)
    return status

def doLogout(i):
    logoutapi='/api/session'
    curlcmd='curl -X DELETE -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + logoutapi + '\" -b ./cookie'+str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    print result  # debug
    if result[0] == 0:
        output=json.loads(result[1])
        if output.has_key("ok"):
            status=output['ok']
        else:
            status = 1
    else:
        outstring = 'Thread is : %s, logout FAIL' % str(i)
        raise LogoutFail(outstring)
    return status

def doLogout_retry(i, counts=3):
    logoutapi='/api/session'
    curlcmd='curl -X DELETE -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + logoutapi + '\" -b ./cookie'+str(i)+' 2>/dev/null'
    c = 0
    while c < counts:
        try:
            result = commands.getstatusoutput(curlcmd)
            if result[0] == 0:
                output = json.loads(result[1])
                if output.has_key("ok"):
                    status = output['ok']
                else:
                    status = 1
            else:
                status = 1
        except Exception:
            status = 1
        finally:
            c += 1
            if status == 0:
                break
            else:
                print "[Thread %s] Logout failed [%s] ..." %(str(i), str(c))
    else:
        outstring = "[Thread %s] Logout failed more than %s times, exit ..." %(str(i), str(counts))
        SaveLog(log_path, outstring)
        print outstring
    return status

def getRestVal(i):
    """ check web online user number """
    # if str(i) not in ok_list:
    #     return
    """restapi='/api/serverinfo/fwinfo'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/sensors'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/serverinfo'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)"""

    # add webonline to user(list)
    restapi='/api/serverinfo/dictnetinfo'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    try:
        result = commands.getstatusoutput(curlcmd)
        print result    # debug
        output=json.loads(result[1])
    except Exception,e:
        outstring = "[Thread %s Exception - Webonline]\n%s" %(str(i), str(e))
        raise LoginFail(outstring)
    else:
        global user     # change global user
        if output.has_key("Webonline"):
            print "Webonline: %s" %output["Webonline"]
            user.append(str(output['Webonline']))
        else:
            outstring = "[Thread %s] Can not find key: Webonline" %str(i)
            raise LoginFail(outstring)

    """restapi='/api/settings/users'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/firmware-info'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/configuration/project'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/serverstate'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/cpuusage'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/memusage'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/logs/event'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/configuration/runtime'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/chassis-status'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/images/level.png'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)"""

def login(i):
    try:
        lock.acquire()
        startTime = datetime.datetime.now()
        a=doLogin(i)
        tmpTime = datetime.datetime.now()
        interval = calc_interval(startTime, tmpTime)    # return string not float
        getRestVal(i)
        # lock.release()
        if a == 0:
            outstring = 'Thread is : %s, login PASS' %str(i)
            timestring = "[Thread %s] Login time : %ss" %(str(i), str(interval))
            SaveLog(log_path, outstring)
            SaveLog(loginTime_path, timestring)
            print outstring
            print timestring
            global ok_list
            ok_list.append(str(i))
        else:
            outstring = 'Thread is : %s, login FAIL' %str(i)
            timestring = "[Thread %s] Login time : failed" %str(i)
            SaveLog(loginTime_path, timestring)
            raise LoginFail(outstring)
    except LoginFail as e:
        SaveLog(log_path, e)
        print e
        print "[Thread %s] Try ping %s ..." %(str(i), bmcip)
        timeout = 30
        t = 0
        ping_start = datetime.datetime.now()
        while float(t/1000) <= timeout:
            ret = ping_test(bmcip)
            ping_tmp = datetime.datetime.now()
            t = calc_interval(ping_start, ping_tmp, flag="ms")     # return string not float
            if ret:
                outstring = "[%s] ping time : %sms" %(bmcip, t)
                SaveLog(log_path, outstring)
                print outstring
                break
        else:
            current = GetNowTime()
            output = "Current time is : %s, %s ping fail exceeds %ss, exit ..." %(current, bmcip, str(timeout))
            SaveLog(log_path, output)
            print output
            os._exit(1)
        ret = CheckLighttpd(bmcip, username, password, log_path)
        outstring = "Check Service lighttpd:\n  [%s]" %ret
        SaveLog(log_path, outstring)
        print outstring
        if not ret:
            if ret == None:     # return None: paramiko ssh command executes fail
                os._exit(2)
            output = "Service lighttpd fail, exit ..."
            SaveLog(log_path, output)
            print output
            os._exit(2)
        else:
            output = "Service lighttpd OK, next loop ..."
            SaveLog(log_path, output)
            print output
    except Exception, e:
        outstring = "[Thread %s Exception - login]\n%s" %(str(i), str(e))
        SaveLog(log_path, outstring)
        print outstring
    finally:
        lock.release()

def logout(i):
    if str(i) not in ok_list:
        return
    try:
        lock.acquire()
        b = doLogout(i)
        # lock.release()
        if b == 0:
            outstring = 'Thread is : %s, logout PASS' % str(i)
            print outstring
            SaveLog(log_path, outstring)
        else:
            outstring = 'Thread is : %s, logout FAIL' % str(i)
            raise LogoutFail(outstring)
    except LogoutFail, e:
        SaveLog(log_path, e)
        print e
        ret = doLogout_retry(i, counts=3)
        if ret == 0:
            outstring = "Re-logout successful."
            SaveLog(log_path, outstring)
            print outstring
        else:
            os._exit(1)     # Logout retry fail, exit ...
    except Exception, e:
        outstring = "[Thread %s Exception - logout]\n%s" %(str(i), str(e))
        SaveLog(log_path, outstring)
        print outstring
    finally:
        lock.release()

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

def main(counts):
    counts += 1
    for count in range(1,counts):
        global token
        token=dict()
        global user
        user=list()
        loopNum = " Loop %s " %str(count)
        print loopNum.center(50, "#")
        outstring='\nThe Login count is : %s, login begin...\n' %str(count)
        SaveLog(log_path, outstring)
        SaveLog(loginTime_path, loopNum.center(50, "#"))
        ret = ping_test(bmcip, count=3)     # ping test before every loop
        if not ret:
            outstring = "IP %s ping fail, please check BMC network ..." %bmcip
            SaveLog(log_path, outstring)
            print outstring
            sys.exit(1)
        ret = check_mc_info(bmcip, username, password)
        current = GetNowTime()
        if not ret:
            output = "Current time is : %s, get BMC version fail !" %current
            SaveLog(log_path, output)
            print output
            # sys.exit(2)
        output = "Current time is : %s, BMC version is %s." %(current, ret)
        SaveLog(log_path, output)
        print output
        for func in [login, logout]:
            threads = []
            if func == login:
                global ok_list
                ok_list = []        # Append thread flag which login successfully
            for i in range(userNum):
                t = threading.Thread(target=func, args=(str(i),))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            # check user number
            if func == login:
                user_int = map(int, user)
                current_user = max(user_int)
                if userNum == current_user:
                    outstring = '\n%s User Check PASS.\n' %str(userNum)
                else:
                    outstring = '\n%s User Check FAIL. Current user: %s.\n' %(str(userNum), current_user)
                SaveLog(log_path, outstring)
                print outstring
            time.sleep(1)
        time.sleep(5)
        count += 1

def parse_time(filename):
    tmp_list = list()
    f = open(filename, "r")
    data = f.readlines()
    f.close()
    for line in data:
        if not line: continue
        if "#" in line: continue
        if "failed" in line: continue
        t = line.split(":")[-1].strip().split("s")[0]
        tmp_list.append(float(t))
    return min(tmp_list), max(tmp_list)

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
    parser.add_option('-H','--host',dest='host',type='string',help='ip address for login eg: 172.16.48.10')
    parser.add_option('-U','--username',dest='username',type='string',help='username for login')
    parser.add_option('-P','--password',dest='password',type='string',help='password for login')
    parser.add_option('-C','--count',dest='count',type='int',help='test count for login, default=1000',default=1000)
    parser.add_option('-M','--max',dest='userNum',type='int',help='max user for login, default=20',default=20)
    opts,args = parser.parse_args()
    current_path = os.path.dirname(os.path.abspath(__file__))
    usage = os.popen("python %s --help" %(sys.argv[0])).read().strip()
    if not opts.host or not opts.username or not opts.password:
        print "\n%s" %usage
        sys.exit(1)
    bmcip=opts.host
    username=opts.username
    password=opts.password
    counts=opts.count
    userNum=opts.userNum
    # define path
    ipmitool = "ipmitool"       # under PATH
    dirname = "log_%s" %(bmcip)
    log_dir = os.path.join(current_path, dirname)
    log_path = os.path.join(log_dir, "Multi-Thread.log")
    loginTime_path = os.path.join(log_dir, "Login_Time.log")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    else:
        del_file(log_dir)
    # main test
    ping_ret = ping_test(bmcip, count=3)
    if not ping_ret:
        output = "[%s] Ping fail, please BMC network ..." %bmcip
        SaveLog(log_path, output)
        print output
        sys.exit(1)
    run("before", bmcip, username, password)
    lock = threading.Lock()
    main(counts)
    bmc_ret = run("after", bmcip, username, password)
    output = "\n[ BMC SEL info ]\n   %s" %bmc_ret
    SaveLog(log_path, output)
    print output
    min_time, max_time = parse_time(loginTime_path)
    output = "\n[ Login Time ]\n"
    output += "  min: %ss\n" %str(min_time)
    output += "  max: %ss\n" %str(max_time)
    SaveLog(log_path, output)
    print output