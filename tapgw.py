#! /usr/bin/env python

import os, sys
import socket
from fcntl import ioctl
from select import select
import dpkt
import struct
import binascii

TUNSETIFF = 0x400454ca
TUNSETPERSIST = TUNSETIFF + 1
TUNSETOWNER   = TUNSETIFF + 2
TUNSETGROUP   = TUNSETIFF + 4

SIOCSIFHWADDR = 0x8924
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI  = 0x1000

TUNMODE = IFF_TAP | IFF_NO_PI
TUN_FD = None


GW_MAC = "52:7b:34:64:00:00"
GW_IP = "10.0.0.1"

CL_MAC = "52:7b:34:64:00:01"
CL_IP = "10.0.0.2"


TUN_DEV_NAME = "tap0"
ID_COUNT = 0x0

arp_cache = {}
clients = []

def mac_ntoa(mac):
   """Print out hunman readable MAC address 
   """
   return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % tuple(map(ord, list(mac)))

def mac_aton(str):
   """ Convert a string representation of a mac address into a network address
   """
   macbytes = [int(i, 16) for i in str.split(':')]
   return struct.pack('6B', *macbytes)

def handle_tap_arp(arp):
   if arp.op == dpkt.arp.ARP_OP_REQUEST:
      print "Arp %s(%s) -> %s(%s)" % (mac_ntoa(arp.sha), socket.inet_ntoa(arp.spa),
                                    mac_ntoa(arp.tha), socket.inet_ntoa(arp.tpa))
      if socket.inet_ntoa(arp.tpa) == GW_IP:
         #build arp response
         arp_p = dpkt.arp.ARP()
         arp_p.op = dpkt.arp.ARP_OP_REPLY
         arp_p.sha = mac_aton(GW_MAC)
         arp_p.spa = socket.inet_aton(GW_IP)
         arp_p.tha = arp.sha
         arp_p.tpa = arp.spa
         packet = dpkt.ethernet.Ethernet()
         packet.src = mac_aton(GW_MAC)
         packet.dst = arp.sha
         packet.data = arp_p
         packet.type = dpkt.ethernet.ETH_TYPE_ARP

      raw = str(packet)
      os.write(TUN_FD, raw) 

      return arp_p

def handle_frame(eth):
   print "Eth frame: %s -> %s" % (mac_ntoa(eth.src), mac_ntoa(eth.dst))
   print(arp_cache)
   if mac_ntoa(eth.dst) != GW_MAC and mac_ntoa(eth.dst) != "ff:ff:ff:ff:ff:ff" and eth.dst not in arp_cache:
      print "WARNING!!, Got frame not target to gateway, ignore." 
      return
   if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
      handle_arp(eth.data)
      return
   if eth.type != dpkt.ethernet.ETH_TYPE_IP:
      print "Non IP packet type(%s) not supported. ignore" % eth.data.__class__.__name__
      return

if __name__ == "__main__":
   TUN_FD = os.open("/dev/net/tun", os.O_RDWR)
   ifs = ioctl(TUN_FD, TUNSETIFF, struct.pack("16sH", TUN_DEV_NAME, TUNMODE))
   ifname = ifs[:16].strip("\x00")

   #set mac addr
   #macbytes = [int(i, 16) for i in MAC.split(':')]
   #ifs = ioctl(TUN_FD, SIOCSIFHWADDR, struct.pack("16sH6B8x", 
   #            ifname, socket.AF_UNIX, *macbytes))

   #persist tap device
   ifs = ioctl(TUN_FD, TUNSETOWNER, 0)
   ifs = ioctl(TUN_FD, TUNSETGROUP, 0) 
   ifs = ioctl(TUN_FD, TUNSETPERSIST, 1)

   print "Allocated interface %s. Configure it and use it" % ifname

   try:
      while 1:
         r = select([TUN_FD],[],[])[0][0]
         if r == TUN_FD:
            print "-------------"
            raw = os.read(TUN_FD, 1500)
            frame = dpkt.ethernet.Ethernet(raw)
            handle_frame(frame)  
   except KeyboardInterrupt:
      print "Stopped by user."

