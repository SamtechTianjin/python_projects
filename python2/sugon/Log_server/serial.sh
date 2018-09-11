#!/usr/bin/env bash
# __author__ = "Sam"


IP=$1
port=$2
main_folder=$3

function move_old_log(){
    local cur_year=`date +"%Y"`
    local cur_month=`date +"%m"`
    local cur_day=`date +"%d"`

    if [ "${cur_month}" -eq 1 ]; then
        old_year=`echo ${cur_year}-1 | bc`
        old_month=12
    else
        old_year=${cur_year}
        old_month=`echo ${cur_month}-1 | bc`
    fi
    old_day=${cur_day}
    for dir in `ls ${main_folder} | egrep '[0-9]{4}-[0-9]{2}-[0-9]{2}'`; do
        tmp_array=(`echo ${dir} | awk -F '-' '{for(i=1;i<=NF;i++){res=res" "$i};print res}'`)
        year=${tmp_array[0]}
        month=${tmp_array[1]}
        day=${tmp_array[2]}
        if [ ${year} -eq ${old_year} ]; then
            if [ ${month} -lt ${old_month} ]; then
                mv ${dir} ${old_folder}
            elif [ ${month} -eq ${old_month} ]; then
                if [ ${day} -le ${old_day} ]; then
                    mv ${dir} ${old_folder}
                fi
            fi 
        elif [ ${year} -lt ${old_year} ]; then
            mv ${dir} ${old_folder}
        fi
    done
}


function save_serial_log(){
    filename="${IP}_${port}.log"

    socat - TCP:${IP}:${port} | while read line
    #nc ${IP} ${port} | while read line
    do
        if ! echo ${line} | grep -q '^[[:space:]]*$'; then	# Don't show blank line
            local timestamp=`date +"%Y/%m/%d %T"`
            local date_folder=`date +"%F"`
            local folder="${main_folder}/${date_folder}"
            local log_path="${folder}/${filename}"
            if [ ! -d "${folder}" ]; then
                mkdir -p ${folder}
                move_old_log
            fi
            if [ ! -f "${log_path}" ]; then
                touch ${log_path}
            fi
            echo "${timestamp}  ${line}" >> ${log_path}
        fi
    done
}

old_folder="${main_folder}/old"
if [ ! -d "${old_folder}" ]; then
    mkdir -p ${old_folder}
fi
cd ${main_folder}
save_serial_log
