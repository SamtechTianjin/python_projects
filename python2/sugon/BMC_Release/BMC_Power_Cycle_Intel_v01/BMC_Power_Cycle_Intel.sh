#!/bin/bash
#==============================Sugon test BMC Power off on Ordinary=================================
# Sugon Modified version v1.0
# Description:script will Cycle BMC Chassis Power repeatedly ,and check webgo KCS iOL and network
# information
# USAGE: ./BMC_Powerup_down-Ordinary.sh <-B BMC IP> < -R chassis power off/on runtime ,default is 12 Hours> < -D power down time > < -U power off after system begin time >
# AUTHOR: Yanshupeng
# CREATED: 08/31/2017
# Release :1.BMC Team want to add retry lan gateway info obtain---2017-08-31
#          2.sdr info ----grep -v "Most recent"
#=================================================================================================
USER=admin
PASSWD=admin

OS_USER=root
OS_PASSWD=111111
ME_retry=false
LAN_number=1
runtime=43200
In_Band=false

function Usage(){
    echo "USAGE:"
    echo -e "\t-h|-help  display help information and exit."
    echo -e "\t-L   LAN number for test, default: 1, please input 1 or 1,8"
    echo -e "\t-B   BMC IP address, which must be set!"
    echo -e "\t-R   Test runtime, default: 43200."
    echo -e "\t-M   select ME retry (maximum=3), default: don't retry ME"
    # In-band test #
    echo -e "\t-I   The in-band test, default: False"
    echo -e "\t-H   OS IP address"
    echo -e "\t-U   OS username, default: root."
    echo -e "\t-P   OS password, default: 111111."
    echo -e "\teg: `basename $0` -B 10.2.35.198 -H 10.2.33.145 -R 3600 -M -I"
}

#==============================================================================================
#The function is parameter analysis
#==============================================================================================

while getopts "L:B:R:U:P:H:MIh" name; do
    case ${name} in
        L)
            LAN_number=$OPTARG
        ;;
        B)
            BMC_IP=$OPTARG
        ;;
        R)
            runtime=$OPTARG
        ;;
        U)
            OS_USER=$OPTARG
        ;;
        P)
            OS_PASSWD=$OPTARG
        ;;
        H)
            OS_HOST=$OPTARG
        ;;
        M)
            ME_retry=true
        ;;
        I)
            In_Band=true
        ;;
        h|help)
            Usage
            exit 0
        ;;
        \?)
            Usage
            exit 1
        ;;
    esac
done

if [ -z "${BMC_IP}" ]; then
    echo -e "\033[1;31mPlease input BMC IP !\033[0m"
    Usage
    exit 1
fi

if ${In_Band}; then
    if [ -z "${OS_HOST}" ]; then
        echo -e "\033[1;31mPlease input SUT OS IP !\033[0m"
        Usage
        exit 1
    fi
fi


LAN_number=`echo ${LAN_number} | awk -F, '{for(i=1;i<=NF;i++){res=res" "$i};print res}'`
echo  "LAN number: ${LAN_number}"


downtime=20
uptime=240

sshtime=90

mylog="./BMC_Power_Cycle-$BMC_IP.log"

#==============================================================================================
#The function is check bmc ip
#==============================================================================================
ping -c 1 $BMC_IP >/dev/null 2>&1
if [ "$?" != 0 ];then
    echo -e "\033[31m Please Check BMC IP ...........................\033[0m"
    exit 1
fi


show_pass()
{
	clear
	echo
	echo
	echo
	echo
	echo
	echo
	echo
	echo
	echo	
	echo	
	show_pass_message " 			XXXXXXX     XXXX     XXXXXX    XXXXXX"
	show_pass_message " 			XXXXXXXX   XXXXXX   XXXXXXXX  XXXXXXXX"
	show_pass_message " 			XX    XX  XX    XX  XX     X  XX     X"
	show_pass_message " 			XX    XX  XX    XX   XXX       XXX"
	show_pass_message " 			XXXXXXXX  XXXXXXXX    XXXX      XXXX"
	show_pass_message " 			XXXXXXX   XXXXXXXX      XXX       XXX"
	show_pass_message " 			XX        XX    XX  X     XX  X     XX"
	show_pass_message " 			XX        XX    XX  XXXXXXXX  XXXXXXXX"
	show_pass_message " 			XX        XX    XX   XXXXXX    XXXXXX"
	echo
	echo
}


#################################################################################################
#                                                                                               #
# Show fail screen                                                                              #
#                                                                                               #
#################################################################################################
show_fail()
{
	#	clear
	echo 
	echo 
	echo 
	echo
	echo 
	echo
	echo -ne "\033[33m 		    $@\033[0m"
	echo
	echo
	show_fail_message " 		XXXXXXX     XXXX    XXXXXXXX  XXX"
	show_fail_message " 		XXXXXXX     XXXX    XXXXXXXX  XXX"
	show_fail_message " 		XXXXXXX    XXXXXX   XXXXXXXX  XXX"
	show_fail_message " 		XX        XX    XX     XX     XXX"
	show_fail_message " 		XX        XX    XX     XX     XXX"
	show_fail_message " 		XXXXXXX   XXXXXXXX     XX     XXX"
	show_fail_message " 		XXXXXXX   XXXXXXXX     XX     XXX"
	show_fail_message " 		XX        XX    XX     XX     XXX"
	show_fail_message " 		XX        XX    XX  XXXXXXXX  XXXXXXXX"
	show_fail_message " 		XX        XX    XX  XXXXXXXX  XXXXXXXX"
	echo 
	echo 
	echo 
	echo
}

#==============================================================================================
#The function is show pass message and fail message
#==============================================================================================
show_pass_message()
{
	tput bold
	TEXT=$1
	echo -ne "\033[32m$TEXT\033[0m"
	echo
}
show_fail_message()
{
	tput bold
	TEXT=$@
	#echo -ne "\033[5;31m$TEXT\033[0m"
	echo -ne "\033[31m$@\033[0m"
	echo
}
#==============================================================================================
#The function is retry check lan print 
#==============================================================================================

retry_lan()
{
    mode=$1
    result=0
    local n=1
    local max=3
    local delay=10
    while true; 
    do
        
        ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" lan print $mode > tmp.log
   
        A=`cat tmp.log | grep "Default Gateway IP" | awk -F ':' '{print $2}' | awk -F '.' '{print $1}' | sed 's/[[:space:]]//g'`
        B=`cat tmp.log | grep "Default Gateway MAC" | awk -F ':' '{print $2}' | sed 's/[[:space:]]//g'`
        
        if [ "$A" != '0' ] && [ "$B" != '0' ];then
             echo "`date +"%D %T"` lan print is normal" >> $mylog
             cat tmp.log
             break
        else 
          {
            if [[ $n -lt $max ]]; then
                echo " Waiting 10s for lan print retry...... Attempt $n/$max:" >> $mylog
                sleep $delay;
            else
                echo " ...after $n attempts,retry count 3 lan print  ,fail" >> $mylog
                result=1
                # exit 1
                break
            fi

          }
        fi
        ((n++))
    done
    
}

#==============================================================================================
#The function is Check BMC Reset time 
#==============================================================================================

retry()
{
    result=0
    local n=1
    local max=1
    local delay=10
    while true; 
    do
        
        echo -e "[\033[32m `date +"%D %T"` Current CHASSIS Power Status is :  \033[0m]" | tee -a $mylog
        ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power status >> $mylog
        A=`ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power status | grep -i "chassis power" | awk '{print $NF}'`
        if [ "$A" == 'on' ];then
             echo "`date +"%D %T"` chassis power is on " | tee -a $mylog
             break
        else 
          {
            if [[ $n -lt $max ]]; then
                echo " Waiting for Chassis Power on...... Attempt $n/$max:" | tee -a $mylog
                sleep $delay;
            else
                echo " ...after $n attempts,Power on status more than 10s ,fail" | tee -a $mylog
                result=1
                break
            fi

          }
        fi
        ((n++))
    done
    return $result
}

#==============================================================================================
#The function is Check BMC reset later Web infomation
#==============================================================================================
CheckWeb()
{
        STEP1=`curl -X POST -d "username="$USER"&password="$PASSWD"" "http://$BMC_IP/api/session" -c ./cookie`
	Tokenvalue=`echo $STEP1 | awk -F ',' '{print $9}'| awk -F ':' '{ if ( $1 == " \"CSRFToken\"" ) {print $2}}' | cut -d " " -f 2 | cut -c 2-9`
	returnvalue=`curl -X GET -H "X-CSRFTOKEN:$Tokenvalue" "http://$BMC_IP/api/serverinfo/fwinfo" -b ./cookie `
    if [ -z "$returnvalue" ];then
        	echo -e "BMC Power off/on to Check Web -------------------------------[\033[5;31mFAIL\033[0m]" |tee -a $mylog
	        exit 1
    else 
		echo -e "BMC Power off/on to Check Web -------------------------------[\033[5;32mPASS\033[0m]" |tee -a $mylog		
	
    fi
      
}



#==============================================================================================
#The function is Check BMC reset and report BMC IP infomation
#==============================================================================================


pingTest()
{
    if [ "$#" -eq 1 ]; then
        local BMC_IP=$1
    fi
    echo "Begin ping.................................."
    echo -e "\033[31m `date +"%D %T"` pinging $BMC_IP...\033[0m" >> testip-"$BMC_IP".log

    ping -c 11 $BMC_IP |tail -n 3 >> testip-"$BMC_IP".log

    num=`cat testip-"$BMC_IP".log | tail -n 3 | grep received | awk -F ',' '{print $2}' | awk  '{print $1}' `
    if [ $num -gt 2 ]; then
        echo -e "\n" >> testip-"$BMC_IP".log
        return 0
    else
        echo -e "\033[31m `date +"%D %T"` Ping "$BMC_IP" FAIL ,more than 10s \033[0m "
        if [ "$#" -eq 0 ]; then     # BMC IP FAIL -> exit
            exit 1
        else                        # OS IP FAIL -> don't exit
            return 1
        fi
    fi

}


#==============================================================================================
#The function is Check System ip Connect is OK
#==============================================================================================
BeginpingSystemTest() 
{
	# Checks system responsiveness to pings
        echo "`date +"%D %T"` pinging $BMC_IP..." | tee -a $mylog
	ping -c 1 $BMC_IP >/dev/null
	rc=$?
	if [[ $rc -eq 0 ]]
	then
		echo -e "[\033[32m `date +"%D %T"` Ping System IP Successful! \033[0m]" | tee -a $mylog
		return 0
	else
		return 1
	fi
}

#==============================================================================================
#The function is Check BMC ip Connect is OK
#==============================================================================================
BeginpingTest() 
{
    echo "`date +"%D %T"` pinging $BMC_IP..." | tee -a $mylog
	ping -c 1 $BMC_IP >/dev/null
	rc=$?
	if [[ $rc -eq 0 ]]
	then
		echo -e "[\033[32m `date +"%D %T"` Ping BMC IP Successful! \033[0m]" | tee -a $mylog
		return 0
	else
		return 1
	fi
}

#==============================================================================================
#The function is Check and diff KCS infomation 
#==============================================================================================

checkKCSConsoleSettings() 
{
	# Compares previously recorded BMC settings to current runs settings
	echo "checking KCS console settings for off/on $run "

	if `diff "KCS-ipmi_settings-$BMC_IP.log" "KCS-ipmi_latest-$BMC_IP.log" >/dev/null`; then
		echo -e "[\033[32m `date '+%D %r'`:KCS BMC_Poweroff/on $run Passed \033[0m] " | tee -a $mylog
		echo " " | tee -a $mylog
	else
		echo -e "[\033[31m `date '+%D %r'`:KCS FAILED during $run, settings changed!! Exiting test!!\033[0m]" | tee -a $mylog
		echo -e "\033[32m Standard information is : \n \033[0m "
                diff "KCS-ipmi_settings-$BMC_IP.log" "KCS-ipmi_latest-$BMC_IP.log" | grep -i "<"

                echo -e "\033[31m Error information is : \n \033[0m "
                diff "KCS-ipmi_settings-$BMC_IP.log" "KCS-ipmi_latest-$BMC_IP.log" | grep -i ">"

                exit 1
	fi
}
#==============================================================================================
#The function is Check and diff iOL infomation
#==============================================================================================

checkiOLConsoleSettings() 
{
	# Compares previously recorded BMC settings to current runs settings
	echo "checking iOL console settings for off/on $run "

	if `diff "iOL-ipmi_settings-$BMC_IP.log" "iOL-ipmi_latest-$BMC_IP.log" >/dev/null`; then
		echo -e "[\033[32m `date '+%D %r'`: iOL BMC_Poweroff/on $run Passed \033[0m] " | tee -a $mylog
		echo " " | tee -a $mylog
	else
		echo -e "[\033[31m `date '+%D %r'`: iOL FAILED during $run, settings changed!! Exiting test!!\033[0m]" | tee -a $mylog
		echo -e "\033[32m Standard information is : \n \033[0m "
                diff "iOL-ipmi_settings-$BMC_IP.log" "iOL-ipmi_latest-$BMC_IP.log" | grep -i "<"

                echo -e "\033[31m Error information is : \n \033[0m "
                diff "iOL-ipmi_settings-$BMC_IP.log" "iOL-ipmi_latest-$BMC_IP.log" | grep -i ">"

                exit 1
	fi
}
#==============================================================================================
# The function is Check and diff iOL ME infomation
#==============================================================================================

checkiOLConsoleMESettings() 
{
	# Compares previously recorded BMC settings to current runs settings
	echo "checking iOL console settings for off/on $run " | tee -a BMC_ME.log

	if `diff "iOL-ipmi_mesettings-$BMC_IP.log" "iOL-ipmi_melatest-$BMC_IP.log" >/dev/null`; then
		echo -e "[\033[32m `date '+%D %r'`: iOL BMC_Poweroff/on  ME $run Passed \033[0m] " | tee -a BMC_ME.log
		echo " " | tee -a BMC_ME.log
	else
		echo -e "[\033[31m `date '+%D %r'`: iOL ME FAILED during $run, settings changed!! Exiting test!!\033[0m]" | tee -a BMC_ME.log
		echo -e "\033[32m Standard information is : \n \033[0m " | tee -a BMC_ME.log
                diff "iOL-ipmi_mesettings-$BMC_IP.log" "iOL-ipmi_melatest-$BMC_IP.log" | grep -i "<" | tee -a BMC_ME.log

                echo -e "\033[31m Error information is : \n \033[0m " | tee -a BMC_ME.log
                diff "iOL-ipmi_mesettings-$BMC_IP.log" "iOL-ipmi_melatest-$BMC_IP.log" | grep -i ">" | tee -a BMC_ME.log
        exit 1
	fi
}

# Compare MachineCheck info
function checkMachineCheckLog(){
    echo "To check MachineCheck log for off/on $run"
    if `diff ./MachineCheckLog/MachineCheck_base.log ./MachineCheckLog/MachineCheck_tmp.log > /dev/null`; then
        echo -e "[\033[32m `date '+%D %r'`: MachineCheck BMC_Poweroff/on $run Passed \033[0m]" | tee -a $mylog
        echo " " | tee -a $mylog
    else
        echo -e "[\033[31m `date '+%D %r'`: MachineCheck FAILED during $run, system config changed!! Exiting test!!\033[0m]" | tee -a $mylog
        echo -e "\033[32m Standard information is : \n \033[0m "
        diff ./MachineCheckLog/MachineCheck_base.log ./MachineCheckLog/MachineCheck_tmp.log | grep -i "<"
        echo -e "\033[31m Error information is : \n \033[0m "
        diff ./MachineCheckLog/MachineCheck_base.log ./MachineCheckLog/MachineCheck_tmp.log | grep -i ">"
        exit 1
    fi
}

#  Add SSH public key to remote authorized_keys
function sshAutoLogin(){
    local IP=$1
    local username=$2
    local password=$3
    # check expect tool
    which expect &> /dev/null
    if [ $? -ne 0 ]; then
        echo -e "\033[1;31mPlease install expect !\033[0m"
        return 1
    fi
    # ping remote ip
    local n=0
    local flag=false
    while [ $n -lt 3 ]; do
        ping -c 1 ${IP} &> /dev/null
        if [ $? -eq 0 ]; then
            flag=true
            break
        fi
        n=$[$n+1]
    done
    if ! ${flag}; then
        echo -e "\033[1;31mTo ping ${IP} FAIL !\033[0m "
        return 2
    fi
    # generate ssh key
    if [ ! -d "/root/.ssh" ]; then
        chmod +x generate_ssh_key.expect
        ./generate_ssh_key.expect > /dev/null
        if [ $? -ne 0 ]; then
            echo -e "\033[1;31mTo generate ssh key FAIL !\033[0m"
            return 3
        fi
    fi
    # copy public key to remote authorized_keys
    chmod +x copy_public_key.expect
    ./copy_public_key.expect ${IP} ${username} ${password} > /dev/null
    if [ $? -ne 0 ]; then
        echo -e "\033[1;31mTo copy public key to remote authorized_keys FAIL !\033[0m"
        return 4
    fi
}

# Read fan speed
function readFanSpeed(){
    local count=$1
    local interval=1
    mkdir -p fan_log
    echo "# Time: `date +"%F %T"`" > fan_log/fan_speed_${count}.log
    echo "# Begin collect fan speed via sdr list #" >> fan_log/fan_speed_${count}.log
    while true; do
        sleep ${interval}
        echo "****************************************" >> fan_log/fan_speed_${count}.log
        ipmitool -I lanplus -H ${BMC_IP} -U ${USER} -P ${PASSWD} sdr list | egrep -i 'FAN[0-9]+_Speed' >> fan_log/fan_speed_${count}.log
        sync
    done
}

# Read degrees C and volts under power off
function readDegreesVolts(){
    local sdr_ret=`ipmitool -I lanplus -H ${BMC_IP} -U ${USER} -P ${PASSWD} sdr list | egrep -i '[0-9]+ degrees C|[0-9]+ volts'`
    if [ ! -z "${sdr_ret}" ]; then
        echo -e "\033[1;31mThe sdr list error under power off.\033[0m" | tee -a $mylog
        echo "${sdr_ret}" >> $mylog
    fi
}

function timeout_cmd(){
    local maxtime=$1
    local CMD=$2
    local timeStart=`date +"%s"`
    local timeInterval=0
    local flag=false
    while [ $timeInterval -le $maxtime ]; do
        $CMD
        local ret=$?
        local timeEnd=`date +"%s"`
        timeInterval=$[${timeEnd}-${timeStart}]
        if [ $ret -eq 0 ]; then
            flag=true
            break
        fi
    done
    if ! $flag; then
        return 1
    fi
    return 0
}

function retry_cmd(){
    local retry_counts=$1
    local cmd=$2
    local count=0
    local flag=false
    while [ $count -lt $retry_counts ]; do
        count=$[$count+1]
        eval ${cmd}
        if [ $? -eq 0 ]; then
            echo -e "\033[1;32m [$cmd] Run successfully. \033[0m" | tee -a $mylog
            flag=true
            break
        else
            echo -e "\033[1;31m [$cmd] Run FAIL, try count: $count.\033[0m" | tee -a $mylog
            sleep 5s
        fi
    done
    if $flag; then
        return 0
    fi
    return 1
}


############################Begin test bmc cold reset##########################################
# Clear Log
ipmitool -H "$BMC_IP" -U "$USER" -P "$PASSWD" sel clear

# Last log save
DATE=`date "+%Y%m%d_%H%M%S"`
mkdir -p "${BMC_IP}-${DATE}"

# backup old log
old_log=(cookie fan_log MachineCheckLog over_time start_time LOG)
mkdir -p "${BMC_IP}-${DATE}-before"
mv *.log "${BMC_IP}-${DATE}-before" &> /dev/null
for l in ${old_log[@]}; do
    mv $l "${BMC_IP}-${DATE}-before" &> /dev/null
done


# Treat unset variables as an error
set -o nounset
if [ ! $(echo $PATH | grep sbin) ]
then
	export PATH=$PATH:/usr/local/sbin:/sbin:/usr/sbin
fi

BeginpingTest
if ! [ $? -eq 0 ]
then
	echo -e "BMC unreachable at start of test! Please check BMC IP , exiting"
	exit 1
fi

power_status=`ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power status`
if echo ${power_status} | grep -iq off ; then
    ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power on
fi

if ${In_Band}; then
    # Config SSH auto login and create machinecheck base
    res=`python check_ssh_service.py ${OS_HOST} ${OS_USER} ${OS_PASSWD}`
    ping_res=`echo $res | awk '{print $1}'`
    ssh_res=`echo $res | awk '{print $2}'`
    if [ "${ping_res}" != "pass" ]; then
        echo "OS network FAIL, exit..." | tee -a $mylog
        exit 1
    elif [ "${ssh_res}" != "pass" ]; then
        echo "SSH login FAIL, exit..." | tee -a $mylog
        exit 1
    fi
    sshAutoLogin ${OS_HOST} ${OS_USER} ${OS_PASSWD}
    ssh ${OS_USER}@${OS_HOST} "mkdir -p /root/sam; rm -rf /root/sam/*"
    scp MachineCheck_Release* ${OS_USER}@${OS_HOST}:/root/sam
    ssh ${OS_USER}@${OS_HOST} "cd /root/sam && tar -zxvf * > /dev/null && cd MachineCheck && chmod +x * && ./install.sh &> /dev/null && ./MachineCheck.sh > MachineCheck_base.log 2> /dev/null"
    mkdir -p MachineCheckLog
    rm -rf MachineCheckLog/*
    scp ${OS_USER}@${OS_HOST}:/root/sam/MachineCheck/MachineCheck_base.log ./MachineCheckLog
fi

# Copy current BMC data into log file
echo "`date '+%D %r'`: Power Cycle will first reboot" | tee -a $mylog

# Capture initial bmc info
ipmitool -H $BMC_IP -U "$USER" -P "$PASSWD" mc info >> $mylog

# Copy current BMC data into log file
echo "`date '+%D %r'`: Storing settings ahead of first reboot" | tee -a $mylog
# ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP mc info > KCS-ipmi_settings-$BMC_IP.log
# ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP raw 0x06 0x01 >> KCS-ipmi_settings-$BMC_IP.log
# for l in ${LAN_number}; do
#     retry_lan $l >> KCS-ipmi_settings-$BMC_IP.log
# done
# ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP sdr info | grep -v "Most recent" >> KCS-ipmi_settings-$BMC_IP.log
# ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP sol info >> KCS-ipmi_settings-$BMC_IP.log

############################iol command BMC ###################################################

ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP mc info >  iOL-ipmi_settings-$BMC_IP.log
ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP raw 0x06 0x01 >> iOL-ipmi_settings-$BMC_IP.log
for l in ${LAN_number}; do
    retry_lan $l >> iOL-ipmi_settings-$BMC_IP.log
done
ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP sdr info | grep -v "Most recent" >> iOL-ipmi_settings-$BMC_IP.log
ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP sol info  >> iOL-ipmi_settings-$BMC_IP.log

if ${ME_retry}; then
    retry_cmd 3 "ipmitool -I lanplus -U $USER -P $PASSWD -H $BMC_IP -b 6 -t 0x2c mc info > iOL-ipmi_mesettings-$BMC_IP.log"
else
    retry_cmd 1 "ipmitool -I lanplus -U $USER -P $PASSWD -H $BMC_IP -b 6 -t 0x2c mc info > iOL-ipmi_mesettings-$BMC_IP.log"
fi
if [ $? -ne 0 ]; then
    echo -e "\033[1;31m To get ME standard FAIL ! \033[0m"
    exit 1
fi


if [ ! -f "endtime-${BMC_IP}.log" ];then
	a=`date +%s`
	let b=$a+$runtime
	echo $b > endtime-${BMC_IP}.log
fi

run=1
endtime=`cat endtime-${BMC_IP}.log`
echo `date +"%D %T"` > start_time

while [ `date +%s` -le "$endtime" ]; do
	commandcycle=0
	echo "`date +"%D %T"` We are on Chassis Power Cycle $run -------------- $run" | tee -a $mylog

#########################  begin Chassis Power CYCLE ##########################################
        
    ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power cycle

    # Save poweroff time
    interval=0
    startTime=`date +%s`
    poweroff_flag=false
    while [ ${interval} -le ${downtime} ]; do
        power_status=`ipmitool -I lanplus -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power status`
        tmpTime=`date +%s`
        interval=$[ ${tmpTime} - ${startTime} ]
        if echo ${power_status} | grep -iq off ; then
            poweroff_string="[Cycle ${run}] Chassis is power off at `date +"%F %T"`, which takes ${interval} seconds."
            echo ${poweroff_string} >> poweroff_time.log
            echo ${poweroff_string} | tee -a $mylog
            poweroff_flag=true
            break
        fi
    done
    if ! ${poweroff_flag}; then
        echo "[Cycle ${run}] Chassis power off FAIL (timeout:${downtime})" | tee -a $mylog
        exit 1
    fi

    pingTest

    # read fan speed
    readFanSpeed $run &
    fan_pid=$!
    echo -e "\033[1;31m CheckFan PID: ${fan_pid} \033[0m" | tee -a $mylog

    sleep $uptime
    retry
    if [ "$result" != "0" ];then
        kill -9 ${fan_pid}
        echo -e "[\033[31m `date +"%D %T"` CHASSIS Power Startup first FAIL \033[0m]" | tee -a $mylog
        echo -e "[\033[31m Begin to Check network ..............................\033[0m]" | tee -a $mylog
        ping -c 10 $BMC_IP
        if [[ "$?" == 0 ]];then
            echo -e "[\033[32m Network is OK ,Begin resend power commmand \033[0m]" | tee -a $mylog
            ipmitool -H $BMC_IP -U "$USER" -P "$PASSWD" chassis power cycle
            commandcycle=1
            readFanSpeed $run &
            fan_pid_again=$!
            echo -e "\033[1;31m CheckFan PID: ${fan_pid_again} \033[0m" | tee -a $mylog
        else
            echo -e "[\033[31m `date +"%D %T"` Network appear problem \033[0m] " | tee -a $mylog
            show_fail
            exit 1
        fi
    fi
    if [[ "$commandcycle" == 1 ]];then
        sleep $downtime
        pingTest
        sleep $uptime
        retry
        if [ "$result" != "0" ];then
            echo -e "[\033[31m `date +"%D %T"` two power cycle still fail ,system may hang up \033[0m]" | tee -a $mylog
            kill -9 ${fan_pid_again}
            show_fail
            exit 1
        fi
    fi

    # stop monitor fan
    if [ $commandcycle -eq 0 ];then
	    kill -9 ${fan_pid}
	elif [ $commandcycle -eq 1 ]; then
	    kill -9 ${fan_pid_again}
    fi

	CheckWeb
	echo "`date '+%D %r'`: Getting settings now" | tee -a $mylog
	echo 
# 	echo "Step 1 - KCS mc print: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
# 	ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP mc info > KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log
# 	echo "Step 2 - KCS FW print: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
# 	ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP  raw 0x06 0x01 >> KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log
# 	for l in ${LAN_number}; do
# 	    echo "KCS lan $l info: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
#         retry_lan $l >> KCS-ipmi_latest-$BMC_IP.log
#     done
# 	echo "Step 3 - KCS lan 1 info: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
#     retry_lan 1 >> KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log
# 	echo "Step 4 - KCS lan 8 info: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
#     retry_lan 8 >> KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log
# 	echo "Step 5 - KCS sdr info: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
#     ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP sdr info | grep -v "Most recent" >> KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log
# 	echo "Step 6 - KCS sol info: $(date "+%Y%m%d_%H%M%S")"|tee -a KCS-ipmi_latest_stderr-$BMC_IP.log
# 	ipmitool -U "$USER" -P "$PASSWD" -H $BMC_IP sol info  >> KCS-ipmi_latest-$BMC_IP.log 2>> KCS-ipmi_latest_stderr-$BMC_IP.log

############################iol command BMC ###################################################
	
	echo "Step 1 - iOL mc print: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
	ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP mc info > iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log 
	echo "Step 2 - iOL FW print: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
	ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP  raw 0x06 0x01 >> iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log
    for l in ${LAN_number}; do
	    echo "iOL lan $l info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
        retry_lan $l >> iOL-ipmi_latest-$BMC_IP.log
    done
# 	echo "Step 3 - iOL lan 1 info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
#     retry_lan 1 >> iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log
# 	echo "Step 4 - iOL lan 8 info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
#     retry_lan 8 >> iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log
    echo "Step 5 - iOL sdr info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
    ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP sdr info | grep -v "Most recent"  >> iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log
	echo "Step 6 - iOL sol info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
	ipmitool -I lanplus -U "$USER" -P "$PASSWD" -H $BMC_IP sol info  >> iOL-ipmi_latest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log
	echo "Step 7 - iOL me bridge info: $(date "+%Y%m%d_%H%M%S")"|tee -a iOL-ipmi_latest_stderr-$BMC_IP.log
	if ${ME_retry}; then
        retry_cmd 3 "ipmitool -I lanplus -U $USER -P $PASSWD -H $BMC_IP -b 6 -t 0x2c mc info > iOL-ipmi_melatest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log"
    else
        retry_cmd 1 "ipmitool -I lanplus -U $USER -P $PASSWD -H $BMC_IP -b 6 -t 0x2c mc info > iOL-ipmi_melatest-$BMC_IP.log 2>> iOL-ipmi_latest_stderr-$BMC_IP.log"
    fi

    # checkKCSConsoleSettings
	checkiOLConsoleSettings
    checkiOLConsoleMESettings
    cp iOL-ipmi_melatest-$BMC_IP.log "$BMC_IP-$DATE"/iOL-ipmi_melatest_$run.log
	# cp KCS-ipmi_latest-$BMC_IP.log "$BMC_IP-$DATE"/KCS-ipmi_latest_$run.log
	# cp KCS-ipmi_latest_stderr-$BMC_IP.log "$BMC_IP-$DATE"/KCS-ipmi_latest_stderr_$run.log
	cp iOL-ipmi_latest-$BMC_IP.log "$BMC_IP-$DATE"/iOL-ipmi_latest_$run.log
	cp iOL-ipmi_latest_stderr-$BMC_IP.log "$BMC_IP-$DATE"/iOL-ipmi_latest_stderr_$run.log

    if ${In_Band}; then
        # MachineCheck
        res=`python check_ssh_service.py ${OS_HOST} ${OS_USER} ${OS_PASSWD}`
        ping_res=`echo $res | awk '{print $1}'`
        ssh_res=`echo $res | awk '{print $2}'`
        if [ "${ping_res}" != "pass" ]; then
            echo "OS network FAIL, exit..." | tee -a $mylog
            exit 1
        elif [ "${ssh_res}" != "pass" ]; then
            echo "SSH login FAIL, exit..." | tee -a $mylog
            exit 1
        fi
        ssh ${OS_USER}@${OS_HOST} "cd /root/sam/MachineCheck && ./MachineCheck.sh > MachineCheck_tmp.log 2> /dev/null"
        scp ${OS_USER}@${OS_HOST}:/root/sam/MachineCheck/MachineCheck_tmp.log ./MachineCheckLog
        checkMachineCheckLog
        mv ./MachineCheckLog/MachineCheck_tmp.log ./MachineCheckLog/MachineCheck_${run}.log
    fi

    sleep 1s
    run=$((${run}+1))
done

# Fan speed plotting
if [ -d fan_log ]; then
    old_dir=`pwd`
    echo "old dir: $old_dir"
    fan_log_list=()
    cd fan_log
    index=0
    for f in `ls`; do
        fan_log_list[$index]=$f
        index=$[$index+1]
    done
    cp ${old_dir}/plotting_sam.py .
    for i in ${fan_log_list[@]}; do
        python plotting_sam.py $i
    done
    cd ${old_dir}
fi

echo -e "[\033[32m `date +"%D %T"` CHASSIS Power Cycle PASS\033[0m]" | tee -a $mylog
show_pass
mkdir LOG
{
mv cookie ./LOG/
mv BMC_ME.log ./LOG/
mv tmp.log ./LOG/
mv endtime-${BMC_IP}.log ./LOG/
mv poweroff_time.log ./LOG/

mv iOL-ipmi_mesettings-${BMC_IP}.log ./LOG/
mv iOL-ipmi_settings-${BMC_IP}.log ./LOG/
mv KCS-ipmi_settings-${BMC_IP}.log ./LOG/
# mv BMC_Power-off_on-${BMC_IP}.log ./LOG/

ipmitool -H "$BMC_IP" -U "$USER" -P "$PASSWD" sel list > ./LOG/sel.log
mv testip-* ./LOG/
echo `date +"%D %T"` > over_time
mv over_time start_time ./LOG/
mv fan_log ./LOG/
mv MachineCheckLog ./LOG/
mv LOG "${BMC_IP}-${DATE}"

rm -f iOL-ipmi_latest-${BMC_IP}.log
rm -f iOL-ipmi_latest_stderr-${BMC_IP}.log
rm -f iOL-ipmi_melatest-${BMC_IP}.log
rm -f KCS-ipmi_latest_stderr-${BMC_IP}.log
rm -f KCS-ipmi_latest-${BMC_IP}.log
} &> /dev/null