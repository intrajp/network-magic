#!/bin/bash
#set -x
#### Author : Shintaro Fujiwara
#### This goes with no warranty, use with your own risk.
####
#### This script should be executed by dhcpd as conditionally with mac address argument 
#### executed in '/etc/dhcp/dhcpd.conf' like below 
####
####  if ( option dhcp-message-type = 1 ) {
####      ...(snip)...
####      execute("/usr/local/bin/record-dhcpdiscover-mac.sh", Clhw);
####  }
####  include "/tmp/dhcp-mac-limit";
####
#### dhcp-message-type 1 is DHCPDISCOVER. So, this script is called every time dhcpd gets DHCPDISCOVER.
#### This script is doing these things 
#### 1. Get mac address from dhcpd.conf as an argument 1 
#### 2. Set an argument 1 as mac address 
#### 3. Write mac address to log file with timestamp  
####  
#### file name: /usr/local/bin/record-dhcpdiscover-mac.sh
#### Should be owned by "dhcpd", group "dhcpd" and security context should be "unconfined_u:object_r:bin_t:s0" 

export LANG=C
## 
MAC_ADDRESS=${1}

if [ -z "${MAC_ADDRESS}" ]; then
    MAC_ADDRESS="11:11:11:11:11:11"
fi 

MAC_PRE="" 
LOG_FILE="/tmp/dhcp-discover.log"

## if logfile does not exist, create it
if [ ! -f ${LOG_FILE} ];then
    touch ${LOG_FILE}
fi

## write mac address with timestamp 
echo "$(date '+%s'),${MAC_ADDRESS}" >> ${LOG_FILE}
