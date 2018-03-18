#!/usr/bin/env python
####
## network-magic is tools for network administrators.
##
## Copyright (C) 2015-2018 Shintaro Fujiwara 
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
####

######### 
## scapy is needed
## I borrowed code from here http://netbuffalo.doorblog.jp/archives/4291860.html and I added some flavor on it.
## Thank you very much.
## How to use this software. 
## You should be root to run this software.
############# HOW TO USE ##############
# python dhclient-multiple.py <numbers>
# If you omit numbers, it would be fixed to 10.
####################################### 

from scapy.all import *
from time import sleep
import threading
import time
 
#################### dhcp ack as a daemon ##############
MESSAGE_TYPE_OFFER = 2
MESSAGE_TYPE_REQUEST = 3
MESSAGE_TYPE_ACK = 5
MESSAGE_TYPE_NAK = 6
MESSAGE_TYPE_RELEASE = 7
 
 
num_offers = 0;
num_acks = 0;
num_naks = 0;
######## you can change here #######
ss = "client-";
conf.iface = "eth0"
####################################
 
class DHCPDHandler(threading.Thread):
 
  def __init__(self):
    threading.Thread.__init__(self) 
 
  def callbak(self, pkt):
    global num_offers
    global num_acks
    global num_naks
    if DHCP in pkt:
      mtype = pkt[DHCP].options[0][1]
      your_ipaddr = pkt[BOOTP].yiaddr
      client_mac = pkt.dst
      if mtype == MESSAGE_TYPE_OFFER:
        num_offers = num_offers + 1
        hostname_str = ss + `num_offers`
        print '%s DHCP OFFER(transaction:%s): %s for %s from %s' % (num_offers,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
        request = (
          Ether(src=client_mac,dst="ff:ff:ff:ff:ff:ff")/
          IP(src="0.0.0.0",dst="255.255.255.255")/
          UDP(sport=68,dport=67)/
          BOOTP(chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)/
          DHCP(options=[
              ('message-type','request'),
              ('requested_addr',your_ipaddr),
              ('hostname',hostname_str),
              ('end')
              ])
          )
        print "Sending DHCP REQUEST..."
        sendp(request,verbose=0)
 
      elif mtype == MESSAGE_TYPE_ACK:
        num_acks = num_acks + 1
        print '%s DHCP ACK(transaction:%s): %s for %s from %s' % (num_acks,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
 
      elif mtype == MESSAGE_TYPE_NAK:
        num_naks = num_naks + 1
        print '%s DHCP NAK(transaction:%s): %s for %s from %s' % (num_acks,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
 
  def run(self):
    sniff(prn=self.callbak, filter="udp and (port 68 or port 67)", store=0)
 
dh = DHCPDHandler()
dh.daemon = True
dh.start()
time.sleep(3)

#### sending DHCPDISCOVER #######
#NUM_MAX_CLIENT = 65535 # up to this value 
NUM_MAX_CLIENT = 10 # default value
#################################
argv = sys.argv
num_argvs = len(argv)
num_clients = NUM_MAX_CLIENT

if num_argvs > 1:
    num_clients = int(argv[1])
if num_clients > 65535:
    print "Too many clients. Less than 65536 would be accepted."
    exit()

print "Starting DHCP DISCOVER ..."

discovers = []

xid_i = 268435457 ## this means 0x10000000
seg1 = '0x01'
seg2 = '0x00'
seg1_state = 0
seg2_state = 0
mac_pre = "00:00:00:00:"
i = 0 
for i in range(num_clients):
    if seg1_state == 1:
        seg1 = '0x00'
        seg1_state = 0
    if seg2_state == 1:
        seg2_i = int(seg2, 16)
        seg2_i += 1
        seg2 = str(hex(seg2_i))
        seg2_state = 0 
    if seg1_state == 0 and seg2_state == 1:
        if seg1 == '0x00':
            continue
        else:
            seg1_i = int(seg1, 16)
            seg1_i += 1
            seg1 = str(hex(seg1_i))
    if seg1 == '0x01' and seg2 == '0x00':
        seg1_i = int(seg1, 16)
        seg1_i = 0
        seg1 = str(hex(seg1_i))
    if seg1 == '0x00':
        seg1_i = int(seg1, 16)
        seg1_i = 0
        seg1 = str(hex(seg1_i))
    else:
        seg1_i = int(seg1, 16)
        seg1_i += 1
        seg1 = str(hex(seg1_i))
    if seg1 == '0xff':
        seg1_state = 1 
        seg2_state = 1 
        #print "seg1 is 0xff !!"
    mac = mac_pre + seg2 + ":" + seg1
    chaddr = ''.join([chr(int(x,16)) for x in mac.split(':')])
    hostname_str = ss + `i` 
    xid_i = xid_i + 1
    discover = (
        Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
        IP(src="0.0.0.0",dst="255.255.255.255")/
        UDP(sport=68,dport=67)/
        #BOOTP(chaddr=chaddr,xid=0x10000000)/
        BOOTP(chaddr=chaddr,xid=xid_i)/
        DHCP(options=[
                ('message-type','discover'),
                ('hostname',hostname_str),
                ('renewal_time',60),
                ('rebinding_time',60),
                ('end')
            ]
            )
        )
    discovers.append(discover)
    print '   ',hostname_str,mac

print "Total clients:",num_clients
time.sleep(5)
print "Here we go. I wait 10 secs."
time.sleep(10)

start = time.time()

for discover in discovers:
    # debug
    #discover.show() ## Just uncomment here for debug
    sendp(discover, verbose=0) # Send packet at layer 2 (comment and uncomment line above for debug)
    #### delaying so that syslog not stopping #####
    time.sleep(0.05)

#end = time.time()
#duration = end - start
#print '%s has elapsed.' % (duration)
#sleep(5.0)

input("")
