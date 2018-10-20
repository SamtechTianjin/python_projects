#!/usr/bin/python
#===================Sugon SIT BMC WEB Update BMC Each=========================================================
# Sugon Modified version v1.0
# Description:
# USAGE: 
# AUTHOR: Yanshupeng
# CREATED: 09/27/2017
#=========================================================================================================
import sys
import os
import commands
import json
import time
import re
import threading
import config
import subprocess
import signal

cur_ver=0
#new_ver=config.New_BMC
bmcver = 0
curbmcver=0
#newbmcver=new_ver
token=0
#imagename='/bmc.ima'
username='admin'
password='admin'
bmcip=0
flag=0
log=0
shellname='testupdateBMC.py'



# Set Shared Lan to dhcp mode via Dedicated Lan after update BMC firmware #
dedicate_lan = config.dedicate_lan
test_SharedLan = config.test_SharedLan

def login_sharelan_dhcp():
    global token
    restapi = '/api/session'
    curl_cmd = 'curl -X POST -d "username=%s&password=%s" "http://%s%s" -c ./cookie 2>/dev/null' %(username, password, dedicate_lan, restapi)
    try:
        child = subprocess.Popen(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output,error = child.communicate()
        if not error:
            output = json.loads(output)
            token = output['CSRFToken']
        else:
            print error
    except Exception as e:
        print "[set share lan dhcp - login]\n%s" %str(e)
    else:
        pass
        # print "Login sucessfully..."

def logout_sharelan_dhcp():
    restapi = '/api/session'
    curl_cmd = 'curl -X DELETE -H "X-CSRFTOKEN:%s" "http://%s%s" -b ./cookie 2>/dev/null' %(token, dedicate_lan, restapi)
    try:
        child = subprocess.Popen(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output,error = child.communicate()
        if error:
            print error
    except Exception as e:
        print "[set share lan dhcp - logout]\n%s" %str(e)
    else:
        pass
        # print "Logout successfully..."

def set_dhcp():
    restapi = "/api/settings/network/2"
    set_sharelan_dhcp_json = {"channel_number":8, "id":2, "interface_name":"eth1", "ipv4_address":"0.0.0.0",\
                              "ipv4_dhcp_enable":1, "ipv4_enable":1, "ipv4_gateway":"0.0.0.0", "ipv4_subnet":"0.0.0.0",\
                              "ipv6_address":"::", "ipv6_dhcp_enable":1, "ipv6_enable":0, "ipv6_gateway":"::",\
                              "ipv6_index":0, "ipv6_prefix":"0", "lan_enable":1, "mac_address":"", "vlan_enable":0,\
                              "vlan_id":"0", "vlan_priority":"0"}
    curl_cmd = "curl -X PUT -H \"X-CSRFTOKEN:%s\" -H \"Content-Type: application/json\" -d \"%s\" \"http://%s%s\" -b ./cookie 2>/dev/null"\
               %(token, str(set_sharelan_dhcp_json), dedicate_lan, restapi)
    try:
        child = subprocess.Popen(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = child.communicate()
        if error:
            print error
    except Exception as e:
        print "[set share lan dhcp]\n%s" % str(e)
    else:
        pass
        # print "Set dhcp successfully..."

def set_lan_to_dhcp():
    login_sharelan_dhcp()
    set_dhcp()
    logout_sharelan_dhcp()
    time.sleep(240)



def _killpid():           
    result=subprocess.Popen(['ps','-ef'],stdout=subprocess.PIPE)
    out,err = result.communicate()
    for line in out.splitlines():
        global shellname
        if  shellname in line:
            pid = int(line.split(None,5)[1])
            print 'pid',pid
            os.kill(pid,signal.SIGKILL)
        else:
            pass

def writelog(logpath,string):
    current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
    output = 'Current time is :' + str(current) + "," + string
    with open(logpath, "a") as text_file:
        text_file.write(output)
        text_file.write('\n')
    

def show(msg):
    string=msg
    while True:
        for j in '-' '\\' '|' '/':
            sys.stdout.write(" %s progress ....: \033[32m %s\r \033[0m" %(string,j))
            time.sleep(0.1)
            sys.stdout.flush()
        global flag 
        if flag == 1:
            flag = 0
            sys.stdout.write(" ")
            sys.stdout.flush()
            break

def show_pass_msg(msg):
    TEXT=str(msg)
    slen=len(TEXT)
    while slen <= 60 :
        TEXT=str(TEXT)+"-"
        slen=len(TEXT)

    TEXT=str(TEXT)+"[ PASS ]"

    print "\033[32m"
    print TEXT
    print "\033[0m"


def show_fail_msg(msg):
    TEXT=str(msg)
    slen=len(TEXT)
    while slen <= 60 :
        TEXT=str(TEXT)+"-"
        slen=len(TEXT)

    TEXT=str(TEXT)+"[ FAIL ]"

    print "\033[31m"
    print TEXT
    print "\033[0m"



def Banner(msg,bmc):
        line   = "#====================================================================#"
        line_1 = "#                                                                    #"
        msg=str(msg)
        bmc=str(bmc)
        x = int((len(line) - len(msg) - 2)/2)
        y = int((len(line)-len('BMC IP :') - len(bmc) - 2)/2)
        tmp_str = "#"
        tmp_str1 = "#"
        for i in range(x):
                tmp_str = tmp_str + " "
        for i in range(y):
                tmp_str1  = tmp_str1 + " "
        tmp_str = tmp_str + msg
        tmp_str1 = tmp_str1 + 'BMC IP :' +str(bmc)
        for i in range(x):
                tmp_str = tmp_str + " "
        for i in range(y):
                tmp_str1= tmp_str1 + " "

        if(len(msg)%2 == 0):
                tmp_str = tmp_str + "#"
        else:
                tmp_str = tmp_str + " #"
        if(len(bmc)%2 == 0):
                tmp_str1 = tmp_str1 + "#"
        else:
                tmp_str1 = tmp_str1 + " #"
  
        print("")
        print('\033[32;1m%s\033[0m'%(line))
        print('\033[32;1m%s\033[0m'%(line_1))
        print('\033[32;1m%s\033[0m'%(tmp_str))
        print('\033[32;1m%s\033[0m'%(tmp_str1))
        print('\033[32;1m%s\033[0m'%(line_1))
        print('\033[32;1m%s\033[0m'%(line))
        #print("")

def sendandgetBMCVer():
    try:
        ipmicmd = 'ipmitool -I lanplus -H ' + bmcip + ' -U ' + username + ' -P ' + password + ' bmc info | grep \"Firmware Revision\" | awk -F \':\' \'{print $2}\'' 
        result = commands.getstatusoutput(ipmicmd)
        if(0!=result[0]):
            print result[1]
            return result[0]
        else:
            global bmcver
            bmcver = str(result[1]).strip()[0:4]
            print bmcver
    except Exception,e :
        print e
        _killpid()    

def Checkfw(fw):
    try:
        ipmicmd = 'ipmitool -I lanplus -H ' + bmcip + ' -U ' + username + ' -P ' + password + ' bmc info | grep \"Firmware Revision\" | awk -F \':\' \'{print $2}\'' 
        result = commands.getstatusoutput(ipmicmd)
        if(0!=result[0]):
            print result[1]
            return result[0]
        else:
            global bmcver
            bmcver = str(result[1]).strip()[0:4]
            if str(fw).strip() == bmcver:
                print 'Check Version :'+str(bmcver)+' is PASS'
                passstring='Check Version :'+str(bmcver)+' is PASS'
                writelog(log,passstring)                
            else:
                print 'Check Version :'+str(bmcver)+'is FAIL'
                failstring='Current Version :'+str(bmcver)+',Corrent Version : '+str(fw)+',Check FAIL'
                writelog(log,failstring)
                sys.exit(1)
       
    except Exception,e :
        print e
        _killpid()    

  

def reset():
    try:
        global token
        restapi='/api/maintenance/reset'
        curlcmd='curl -X POST -H \"X-CSRFTOKEN:' +token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)  
        global token
        if(0!=result[1]):
            status=1
        else:
            status=0
        if status == 0:
            global flag
            flag =1
        else:
            show_fail_msg('BMC WEB Reset')
            print "\033[31m"
            print 'Please check BMC IP is OK .......'
            print "\033[0m"''
            global flag
            flag = 1
            sys.exit(1)
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    



def doLogin():
    try:
        restapi='/api/session'
        curlcmd='curl -X POST -d \"username=' + username + '&password=' + password + '\" ' + '\"http://' + bmcip + restapi + '\" -c ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)
        output=json.loads(result[1])
        global token
        if(output.has_key('ok')):
            token=output['CSRFToken']
            status=output['ok']
        else:
            status=1
        if status == 0:
            global flag
            flag =1
        else:
            show_fail_msg('BMC WEB Login')
            print "\033[31m"
            print 'Please check BMC IP is OK .......'
            print "\033[0m"''
            global flag
            flag = 1
            sys.exit(1)
    except Exception,e :
        print result
        print e
        global flag
        flag=1
        _killpid()    



def doLogout():
    try:
        global token
        restapi='/api/session'
        curlcmd='curl -X DELETE -H \"X-CSRFTOKEN:' +token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)
        if(0!=result[0]):
            print result[1]
            print 'logout fail'
        else:
            pass
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    

   
def prepareFlashArea():
    try:
        global token
        restapi='/api/maintenance/flash'
        curlcmd='curl -X PUT -H \"X-CSRFTOKEN:' +token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)  
        if(0!=result[0]):
            print result[1]
            status=1
        else:
            status=0
        if status == 0:
            global flag 
            flag=1
        else:
            show_fail_msg('Prepare phase')
            print "\033[31m"
            print 'Check Whether BMC supports BMC upgrade,or Network ping ok.......'
            print "\033[0m"''
            global flag
            flag=1
            sys.exit(1)
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    



def uploadBMCRom(filename):
    try:
        global token
        restapi='/api/maintenance/firmware'
        curlcmd='curl -F \"fwimage=@' + filename + '\" -H \"X-CSRFTOKEN:' + token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)  
        output=json.loads(result[1])
        if(output.has_key('cc')):
            status=output['cc']
        else:
            status=1
        if status == 0:
            global flag
            flag=1
        else:
            show_fail_msg('Upload phase')
            print "\033[31m"
            print 'Check Whether BMC supports BMC upgrade,or Network ping ok.......'
            print "\033[0m"''
            global flag
            flag=1
            sys.exit(1)
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    



def verifyBMCRom():
    try:
        global token
        restapi='/api/maintenance/firmware/verification'
        curlcmd='curl -X GET -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:' +token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)  
        status=0
        if status == 0:
            global flag
            flag=1
        else:
            show_fail_msg('Verify phase')
            print "\033[31m"
            print 'Check Whether BMC supports BMC upgrade,or Network ping ok.......'
            print "\033[0m"''
            global flag
            flag=1
            sys.exit(1)
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    


def flashBMC():
    try:
        global token
        restapi='/api/maintenance/firmware/upgrade'
        curlcmd='curl -X PUT -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:' +token + '\"' + ' -d \'{\"preserve_config\":0,\"flash_status\":1}\'  \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
        result=commands.getstatusoutput(curlcmd)  
        if(0!=result[0]):
            print result[1]
            status=1
        else:    
            status=0

        if status == 0:
            global flag
            flag=1
        else:
            show_fail_msg('Flash phase')
            print "\033[31m"
            print 'Check Whether BMC supports BIOS upgrade,or Network ping ok.......'
            print "\033[0m"''
            global flag
            flag=1
            sys.exit(1)
    except Exception,e :
        print e
        global flag
        flag=1
        _killpid()    



def getFlashStatus():
    global token
    restapi='/api/maintenance/firmware/flash-progress'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' +token + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie 2>/dev/null'
    time.sleep(5)
    result=commands.getstatusoutput(curlcmd)  
    try:
        eval(result[1])
    except Exception,e :
        print "Response not in json format"
        sys.exit(1)

    output=json.loads(result[1])
    if(output.has_key('progress')):
        progress=output['progress']
        sys.stdout.write(" Current Update Progress : \033[32m %s\r \033[0m" %(progress))
        sys.stdout.flush()
    return progress

def main1(geshu): 
    try:
        os.system('clear')
        sendandgetBMCVer()
        global bmcip
        Banner('- Sugon SIT BMC WEB Update BMC High FW-',bmcip)
        line='Current Update Count is : '+str(geshu)
        print('\033[32;1m%s\033[0m'%(line))
        #global bmcver
        #curbmcver=bmcver
        #print ' Current BMC Version    : ',curbmcver ,'   Now Update BMC Version :',newbmcver
        threads = []
        t1 = threading.Thread(target=doLogin)   
        t1.start()
        threads.append(t1)
        t1_1 = threading.Thread(target=show,args=('1---Begin Login BMC Web',)) 
        t1_1.start()
        threads.append(t1_1)
        for t in threads:
            t.join(20)
        sys.stdout.flush()
        writelog(log,'1---Begin Login BMC Web....done')
        print '1---Begin Login BMC Web....done                                \n'
       
        threads = []
        t2 = threading.Thread(target=prepareFlashArea)   
        t2.start()
        threads.append(t2)
        t2_1 = threading.Thread(target=show,args=('2---Prepare update BMC',)) 
        t2_1.start()
        threads.append(t2_1)
        for t in threads:
            t.join(90)
        sys.stdout.flush()
        writelog(log,'2---Prepare update BMC....done')
        print '2---Prepare update BMC....done                                \n'
        threads = []
        t3 = threading.Thread(target=uploadBMCRom,args=('./bmc1.ima',))   
        t3.start()
        threads.append(t3)
        t3_1 = threading.Thread(target=show,args=('3---Upload BMC FW',)) 
        t3_1.start()
        threads.append(t3_1)
        for t in threads:
            t.join(60)
        sys.stdout.flush()
        writelog(log,'3---Update BMC FW ....done')
        print '3---Upload BMC FW ....done                                    \n'
        threads = []
        t4 = threading.Thread(target=verifyBMCRom)   
        t4.start()
        threads.append(t4)
        t4_1 = threading.Thread(target=show,args=('4---Verify BMC FW',)) 
        t4_1.start()
        threads.append(t4_1)
        for t in threads:
            t.join(100)
        sys.stdout.flush()
        writelog(log,'4---Verify BMC FW ....done')
        print '4---Verify BMC FW ....done                                    \n'
        threads = []
        t5 = threading.Thread(target=flashBMC)   
        t5.start()
        threads.append(t5)
        t5_1 = threading.Thread(target=show,args=('5---Flash BMC FW',)) 
        t5_1.start()
        threads.append(t5_1)
        for t in threads:
            t.join(20)
        sys.stdout.flush()
        writelog(log,'5---Flash BMC FW ....done')
        print '5---Flash BMC FW ....done                                     \n'
        count=0
        while(count<300):
            ret=getFlashStatus()
            if('Completed.'==ret):
                sys.stdout.write(" ")
                sys.stdout.flush()
                show_pass_msg('Update BMC')
                writelog(log,'Update BMC PASS')
                break
            elif(-1==ret):
                show_fail_msg('Update BMC')
                break
            else:
                pass           
            time.sleep(1)
            count += 1        
        doLogout()
    except Exception,e :
        print e
        _killpid()    

def main2(geshu): 
    try:
        os.system('clear')
        sendandgetBMCVer()
        global bmcip
        Banner('- Sugon SIT BMC WEB Update BMC Lower FW-',bmcip)
        line='Current Update Count is : '+str(geshu)
        print('\033[32;1m%s\033[0m'%(line))
        writelog(log,line)
        #global bmcver
        #curbmcver=bmcver
        #print ' Current BMC Version    : ',curbmcver ,'   Now Update BMC Version :',newbmcver
        threads = []
        t1 = threading.Thread(target=doLogin)   
        t1.start()
        threads.append(t1)
        t1_1 = threading.Thread(target=show,args=('1---Begin Login BMC Web',)) 
        t1_1.start()
        threads.append(t1_1)
        for t in threads:
            t.join(20)
        sys.stdout.flush()
        writelog(log,'1---Begin Login BMC Web....done')
        print '1---Begin Login BMC Web....done                                \n'
       
        threads = []
        t2 = threading.Thread(target=prepareFlashArea)   
        t2.start()
        threads.append(t2)
        t2_1 = threading.Thread(target=show,args=('2---Prepare update BMC',)) 
        t2_1.start()
        threads.append(t2_1)
        for t in threads:
            t.join(90)
        sys.stdout.flush()
        writelog(log,'2---Prepare update BMC....done')
        print '2---Prepare update BMC....done                                \n'
        threads = []
        t3 = threading.Thread(target=uploadBMCRom,args=('./bmc2.ima',))   
        t3.start()
        threads.append(t3)
        t3_1 = threading.Thread(target=show,args=('3---Upload BMC FW',)) 
        t3_1.start()
        threads.append(t3_1)
        for t in threads:
            t.join(60)
        sys.stdout.flush()
        writelog(log,'3---Update BMC FW ....done')
        print '3---Upload BMC FW ....done                                    \n'
        threads = []
        t4 = threading.Thread(target=verifyBMCRom)   
        t4.start()
        threads.append(t4)
        t4_1 = threading.Thread(target=show,args=('4---Verify BMC FW',)) 
        t4_1.start()
        threads.append(t4_1)
        for t in threads:
            t.join(100)
        sys.stdout.flush()
        writelog(log,'4---Verify BMC FW ....done')
        print '4---Verify BMC FW ....done                                    \n'
        threads = []
        t5 = threading.Thread(target=flashBMC)   
        t5.start()
        threads.append(t5)
        t5_1 = threading.Thread(target=show,args=('5---Flash BMC FW',)) 
        t5_1.start()
        threads.append(t5_1)
        for t in threads:
            t.join(20)
        sys.stdout.flush()
        writelog(log,'5---Flash BMC FW ....done')
        print '5---Flash BMC FW ....done                                     \n'
        count=0
        while(count<300):
            ret=getFlashStatus()
            if('Completed.'==ret):
                sys.stdout.write(" ")
                sys.stdout.flush()
                show_pass_msg('Update BMC')
                writelog(log,'Update BMC PASS')
                return 0
                break
            elif(-1==ret):
                show_fail_msg('Update BMC')
                break
            else:
                pass           
            time.sleep(1)
            count += 1        
        
    except Exception,e :
        print e
        _killpid()    


if __name__ == '__main__':
    curlcmd='echo 1 > count'
    result=commands.getstatusoutput(curlcmd)  
    bmcip=config.BMC_IP[0]
    if not os.path.exists("LOG"):
        os.makedirs("LOG")
    global log
    log='LOG/'+str(bmcip)+'-update.log'
    sendandgetBMCVer()
    global bmcver
    output = '#===========================================================\n'
    output2 ='                    Update Curl Each BMC FW \n'
    output3 ='                 BMC IP : '+str(bmcip) +'\n' 
    output4 ='             Begin BMC Version    : '+str(bmcver)+'\n'
    output6 ='#==========================================================\n '
    # global log
    with open(log, "a") as text_file:
        text_file.write(output)
        text_file.write(output2)
        text_file.write(output3)
        text_file.write(output4)
        text_file.write(output6)
        text_file.write('\n')
    try:
        i=1
        highfw=config.highfw
        lowfw=config.lowfw
        count=config.Count
        while i <= int(count) :
            sendandgetBMCVer()
            global bmcver
            if str(bmcver).strip() == str(highfw).strip():
                main2(i)
                time.sleep(240)
                if test_SharedLan == 1:
                    set_lan_to_dhcp()
                Checkfw(str(lowfw).strip())
                writelog(log,'\n\n')

            elif str(bmcver).strip() == str(lowfw).strip():
                main1(i)
                time.sleep(240)
                if test_SharedLan:
                    set_lan_to_dhcp()
                Checkfw(str(highfw).strip())
                writelog(log,'\n\n')

            else:
                print 'error bmc version'
            i=i+1
        line='ALL BMC WEB Curl Update FW is ----------------------------------[PASS]'
        print('\033[32;1m%s\033[0m'%(line))
        writelog(log,'ALL Update BMC PASS')
    except Exception,e :
        print e
        _killpid()    


