#!/bin/bash

#### Program Name: dhcpdiscover-mac-limitter
#### Description: limits vogus user which repeatedly sends DHCPDISCOVER packet 
####
#### This comes with no wrranty, use with your own risk.
#### Author : Shintaro Fujiwara
####
#### This script should be executed in background
#### Should be executed from 'inotify_dhcp_discover'" 
#### 1. this script writes mac address to config file which should be ignored 
#### 2. this script does not remove already appended mac address list  

export LANG=C
set -x
MAC_ADDRESS=$1

# should be owned by dhcpd:dhcpd
# security context should be unconfined_u:object_r:dhcp_etc_t:s0  
CONF_FILE="/tmp/dhcp-mac-limit"

# should be owned by dhcpd:dhcpd
# security context should be unconfined_u:object_r:dhcpd_tmp_t:s0  
LOG_FILE="/tmp/dhcp-discover.log"

LOG_LINES_LIMIT=100
LOG_LINES_CURR=0
REPETITION_CURR=0

## adding host to conf file
add_malicious_host_to_conf_file()
{
    local mac_address=${1}
    local cnt=${2}
## no indent because utilizing 'here document'
cat <<EOF >> ${CONF_FILE}
host malicious_${cnt} {
  hardware ethernet ${mac_address}
;
  ignore booting;
}
EOF
}

#### function part ####

## this function adds mac address to config file
add_mac_try()
{
    local new_mac=${1}
    local existing_mac=""
    local existing_mac_pre=""
    local cnt=0
    while read line
    do
        if [[ ${line} =~ "host" ]]; then
            break
        fi
    done < "${CONF_FILE}"
    echo "${line}"
    cnt=`echo ${line} | awk -F"_" '{ print $2 }' | awk -F" " '{ print $1 }'`
    echo "cnt:${cnt}"
    if [ -z ${cnt} ]; then
        cnt=0
    else
        cnt=$(($cnt +1))
    fi

    ## if there no list, add it to the list
    if [ ${cnt} -eq 0 ]; then
        add_malicious_host_to_conf_file "${new_mac}" "${cnt}"
        ## now, remake the logfile with proper attributes 
        remake_log_file
        ## restart dhcpd with force-reload
        service dhcpd force-reload 
    ## if there exists list, loop through list and if it is new to the list, add it to the list
    else
        local existing_mac_arr=()
        while read line
        do
            if [[ ${line} =~ "hardware" ]]; then
                break
            fi
        done < ${CONF_FILE}

        existing_mac_pre=`echo ${line} | awk -F" " '{ print $3 }'`
        existing_mac_arr+=(${existing_mac_pre})

        local existing_mac_arr_numbers="${#existing_mac_arr[*]}"

        for existing_mac in ${existing_mac_arr[@]}
        do
            ## if mac address does not match any of them already exists, add to the list
            if [ ${existing_mac} != ${new_mac} ]; then
                add_malicious_host_to_conf_file "${new_mac}" "${cnt}"
                ## now, remake the logfile with proper attributes 
                remake_log_file
                ## restart dhcpd with force-reload
                service dhcpd force-reload 
                break
            ## if mac address is identical with existing mac
            elif [ "${new_mac}" = "${existing_mac}" ]; then
                ## now, remake the logfile with proper attributes 
                remake_log_file
            ## this should not happen 
            else
                ## now, remake the logfile with proper attributes 
                remake_log_file
            fi
        done
    fi
}

## remaking log file
remake_log_file()
{
    rm ${LOG_FILE}
    touch ${LOG_FILE}
    chown dhcpd:dhcpd ${LOG_FILE}
    chcon unconfined_u:object_r:dhcpd_tmp_t:s0 ${LOG_FILE} 
}

#### end function part ####

#### main part ####
add_mac_try "${MAC_ADDRESS}"

LOG_LINES_CURR=$(cat ${LOG_FILE} | wc -l)
if [ "${LOG_LINES_CURR}" -gt "${LOG_LINES_LIMIT}" ]; then
    ## now, remake the logfile with proper attributes 
    remake_log_file
fi

#### end main part ####
