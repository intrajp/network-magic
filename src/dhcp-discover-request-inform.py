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
# python dhcp-discover-request-inform.py
# You can change three types manually, DISCOVER,REQUEST,INFORM.
####################################### 
 
from scapy.all import *
import threading
import time
 
MESSAGE_TYPE_OFFER = 2
MESSAGE_TYPE_REQUEST = 3
MESSAGE_TYPE_ACK = 5
MESSAGE_TYPE_NAK = 6
MESSAGE_TYPE_RELEASE = 7
 
#### set interface name properly ####
#conf.iface = "eth0"
conf.iface = "enp0s3"
 
num_offers = 0;
num_acks = 0;
num_naks = 0;
 
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
        print '%s DHCP OFFER(transaction:%s): %s for %s from %s' % (num_offers,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
        request = (
          Ether(src=client_mac,dst="ff:ff:ff:ff:ff:ff")/
          IP(src="0.0.0.0",dst="255.255.255.255")/
          UDP(sport=68,dport=67)/
          BOOTP(chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)/
          DHCP(options=[('message-type','request'),('requested_addr',your_ipaddr),('end')])
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
time.sleep(0.5)

#### set mac address you want or make it random
mac = "xx:xx:xx:xx:xx:xx"
mac = str(RandMAC())
chaddr = ''.join([chr(int(x,16)) for x in mac.split(':')])
 
########  select from here ############
discover = (
    Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
    IP(src="0.0.0.0",dst="255.255.255.255")/
    UDP(sport=68,dport=67)/
    BOOTP(chaddr=chaddr,xid=random.randint(0, 0xFFFF))/
    DHCP(options=[('message-type','discover'),('end')])
    )

request = (
    Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
    IP(src="client_ip",dst="server_ip")/
    UDP(sport=68,dport=67)/
    BOOTP(chaddr=chaddr,xid=random.randint(0, 0xFFFF))/
    DHCP(options=[('message-type','request'),('requested_addr','client_ip'),('end')])
    )

print "Sending DHCP DISCOVER..."
print "Sending DHCP REQUEST..."
print "Sending DHCP INFORM..."

sendp(discover,verbose=0)
sendp(request,verbose=0)
sendp(inform,verbose=0)
 
input("")
