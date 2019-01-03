#!/usr/bin/env bash
# __author__ = "Sam"


function show_fail_message(){
    message=$@
    echo -e "\033[1;31m ${message} \033[0m"
}

function show_pass_message(){
    message=$@
    echo -e "\033[1;32m ${message} \033[0m"
}

function usage(){
    show_fail_message "Usage: bash $0 < serial|system > < IP > < port > < log path > !"
}


which screen &> /dev/null
if [ $? -ne 0 ]; then
    show_fail_message "Please install tool: screen !"
    exit 1
fi

if [ $# -ne 4 ]; then
    usage
    exit 1
elif [ "$1" != "serial" -a "$1" != "system" ]; then
    usage
    exit 1
fi

log_type=$1
IP=$2
port=$3
log_path=$4
session_name="${IP}_${port}"
current_path=$(cd `dirname $0`; pwd)

if [ "${log_type}" == "serial" ]; then
    script="${current_path}/serial.sh"
elif [ "${log_type}" == "system" ]; then
    script="${current_path}/system.sh"
fi

# Flush process
count=3
while [ $count -gt 0 ];do
    flush_process=`screen -ls | grep SerialLogFlush`
    if [ -z "${flush_process}" ]; then
        flush_session="SerialLogFlush"
        flush_cmd="python ${current_path}/serial_log_update.py ${log_path}"
        screen -dmS ${flush_session}
        if [ $? -eq 0 ];then
            screen -S ${flush_session} -p 0 -X stuff "${flush_cmd}\n"
            sleep 0.5
            temp=`ps -ef | grep serial_log_update.py | grep -v grep`
            if [ -n "$temp" ];then
                break
            else
                screen -S ${flush_session} -X quit
            fi
        fi
    fi
    let count=$count-1
    sleep 0.5
done


# Auto check process
count=3
while [ $count -gt 0 ];do
    check_process=`screen -ls | grep AutoCheckSerialLog`
    if [ -z "${check_process}" ]; then
        check_session="AutoCheckSerialLog"
        check_cmd="python ${current_path}/Auto_Collect_Serial_log.py ${log_path}"
        screen -dmS ${check_session}
        if [ $? -eq 0 ];then
            screen -S ${check_session} -p 0 -X stuff "${check_cmd}\n"
            sleep 0.5
            temp=`ps -ef | grep Auto_Collect_Serial_log.py | grep -v grep`
            if [ -n "$temp" ];then
                break
            else
                screen -S ${check_session} -X quit
            fi
        fi
    fi
    let count=$count-1
    sleep 0.5
done


# Monitor process
monitor_process=`screen -ls | grep ${session_name}`
if [ -z "${monitor_process}" ];then
    cmd="bash ${script} ${IP} ${port} ${log_path}"
    screen -dmS ${session_name}
    if [ $? -eq 0 ];then
        screen -S ${session_name} -p 0 -X stuff "${cmd}\n"
    fi
fi

sleep 0.5

