import os
import sys
import socket
import struct
import logging
from fcntl import ioctl
from select import select


logging.basicConfig(level = logging.DEBUG)


# Socket consts
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12000
MAGIC = "CoproAnal"
server = (SERVER_IP, SERVER_PORT)

MTU = 1500
ETHERNET_HEADER_SIZE = 18
PACKET_SIZE = MTU + ETHERNET_HEADER_SIZE


# TAP consts
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

TUN_DEV_NAME = "tap0"

if __name__ == "__main__":
    
    # Setting up client socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.setblocking(False)
    client.sendto(MAGIC, server)
    connected = False
    logging.debug("Client socket created")
    
    # Setting up tap interface
    TUN_FD = os.open("/dev/net/tun", os.O_RDWR)
    ifs = ioctl(TUN_FD, TUNSETIFF, struct.pack("16sH", TUN_DEV_NAME, TUNMODE))
    ifname = ifs[:16].strip("\x00")

    #persist tap device
    ifs = ioctl(TUN_FD, TUNSETOWNER, 0)
    ifs = ioctl(TUN_FD, TUNSETGROUP, 0) 
    ifs = ioctl(TUN_FD, TUNSETPERSIST, 1)

    logging.debug("Interface {}. Configure it and use it".format(ifname))
    
    try:
        while True:
            r, w, e = select([client, TUN_FD], [], [])
            
            for sock in r:
                if sock == client:
                    data, peer = client.recvfrom(PACKET_SIZE)
                    if data == MAGIC and not connected:
                        connected = True
                        logging.debug("Connected to server: {}".format(server))
                    elif data and connected:
                        os.write(TUN_FD, data)
                        logging.debug("Recived server data. Write to TAP.")
                    else:
                        logging.debug("Trash data from server")
                elif sock == TUN_FD:
                    client.sendto(os.read(TUN_FD, PACKET_SIZE), server)
                    logging.debug("Data sent to server")
    except KeyboardInterrupt:
        logging.debug("Client stopped by user") 




