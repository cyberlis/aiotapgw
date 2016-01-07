import win32file
import pywintypes
import win32event
import win32api
import winreg as reg
import queue, threading
import time
from select import select
import socket
import sys

mainTaskQueue = queue.Queue()
ethernetMTU = 1518
verboseMode = True
adapterReadCreator = 1





# Socket consts
SERVER_IP = '192.168.100.16'
SERVER_PORT = 12000
MAGIC = b'CoproAnal'
server = (SERVER_IP, SERVER_PORT)

MTU = 1500
ETHERNET_HEADER_SIZE = 18
PACKET_SIZE = MTU + ETHERNET_HEADER_SIZE




def alert(verbose, nonverbose =""):
    if verboseMode or nonverbose == "_all":
        print(verbose)
    elif nonverbose:
        print(nonverbose)

#This class encapsulates the TUNTAP object (mainly so I can collapse it and not have to look at this cryptic eyesore)
#Even though there were some examples online, they only provided partial functionality, and were exceedingly cryptic
#So this was written as an alternative
class tuntapWin:

    #A useful constant
    adapterKey = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    
    #I would love to find a better way to do these
    #---------------------------------------------
    """By default we operate as a "tap" virtual ethernet
    802.3 interface, but we can emulate a "tun"
    interface (point-to-point IPv4) through the
    TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT or
    TAP_WIN_IOCTL_CONFIG_TUN ioctl."""
    def CTL_CODE(self, device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method
    def TAP_CONTROL_CODE(self, request, method):
        return self.CTL_CODE(34, request, method, 0)
    #---------------------------------------------
        
    #Returns the GUID of the tap device, or False if it cannot be found
    def getDeviceGUID(self):
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.adapterKey) as adapters:
            try:
                for i in range(1000):
                    keyName = reg.EnumKey(adapters, i)
                    with reg.OpenKey(adapters, keyName) as adapter:
                        try:
                            componentID = reg.QueryValueEx(adapter, 'ComponentId')[0]
                            if componentID == 'tap0801' or componentID == 'tap0901':
                                return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                        except WindowsError:
                            pass
            except WindowsError:
                pass
            
            #If no key was found
            alert("Failed to locate a TAP device in the windows registry.", "_all")
            return False
    
    def __init__(self, autoSetup = False):
    
        #These can be used, or not.
        self.myGUID = ""
        self.myInterface = 0
        self.trimEthnHeaders = False
        self.ethernetMTU = 1500
        self.myMACaddr = b""
        self.writeDataQueue = queue.Queue()
        self.dataThreads = []
        
        #Set up an overlapped structure for deviceIoControl
        #This originally created an array of overlapped stuctures used throughout this class, but now threads create their own for safety
        self.overlapped = pywintypes.OVERLAPPED()
        self.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        
        #Some function encapsulation
        #In case anyone else reads this, the tap control codes use the windows io control code interface to pass special
        #codes to the tap driver. Also, some constants are borrowed from the win iocontrol library (which are simply replaced with numbers here) 
        self.TAP_IOCTL_GET_MAC =                     self.TAP_CONTROL_CODE(1, 0)
        self.TAP_IOCTL_GET_VERSION =                 self.TAP_CONTROL_CODE(2, 0)
        self.TAP_IOCTL_GET_MTU =                     self.TAP_CONTROL_CODE(3, 0)
        self.TAP_IOCTL_GET_INFO =                    self.TAP_CONTROL_CODE(4, 0)
        self.TAP_IOCTL_CONFIG_POINT_TO_POINT =       self.TAP_CONTROL_CODE(5, 0)        #This call has been obsoleted, use CONFIG_TUN instead
        self.TAP_IOCTL_SET_MEDIA_STATUS =            self.TAP_CONTROL_CODE(6, 0)
        self.TAP_IOCTL_CONFIG_DHCP_MASQ =            self.TAP_CONTROL_CODE(7, 0)
        self.TAP_IOCTL_GET_LOG_LINE =                self.TAP_CONTROL_CODE(8, 0)
        self.TAP_IOCTL_CONFIG_DHCP_SET_OPT=          self.TAP_CONTROL_CODE(9, 0)
        self.TAP_IOCTL_CONFIG_TUN =                  self.TAP_CONTROL_CODE(10, 0)
        
        #Whether the object should attempt to initialize itself
        if autoSetup:
            self.myGUID = self.getDeviceGUID()
            
            #Force close if no adapter was found
            if not self.myGUID:
                alert("Fatal error: could not locate tap adapter. (Is the adapter properly installed?) \nAutoclosing in 5 seconds.", "_all")
                time.sleep(5)
                sys.exit()
            
            alert("Tap GUID: " + self.myGUID)
            
            self.myInterface = self.createInterface()
            print(self.myInterface)
            if (self.myInterface):
                #Connect media, and get our MAC address
                self.setMediaConnectionStatus(True)
                self.updateMAC()
            else:
                alert("Failed to interface with TAP adapter. Exiting in 5 seconds.", "_all")
                time.sleep(5)
                sys.exit()
            
            self.dataThreads.append(threading.Thread(target=self.dataListenerThread, args=(mainTaskQueue, ethernetMTU), daemon = True))
            self.dataThreads.append(threading.Thread(target=self.dataWriterThread, args=(self.writeDataQueue,), daemon = True))
            self.dataThreads[0].start()
            alert('Data listener thread started as daemon.')
            self.dataThreads[1].start()
            alert('Data injector thread started as daemon.')
            
    
    #A function to make sure we close our handle and reset media status
    def __del__(self):
        win32file.CloseHandle(self.myInterface)
        self.setMediaConnectionStatus(False)
        print("Handle closed, media disconnected.")
    
    #A function to set the media status as either connected or disconnected in windows
    def setMediaConnectionStatus(self, toConnected):
        #In most TunTap examples, the following line omits an overlapped structure. However, the windows documentation says it should be used
        #if the handle is created with the overlapped flag set. The offsets should be initialized to zero, then left unused.
        win32file.DeviceIoControl(self.myInterface, self.TAP_IOCTL_SET_MEDIA_STATUS, toConnected.to_bytes(4, "little"), None, self.overlapped)
    
    #A simple function to update/return the MAC address
    def updateMAC(self):
        #The following command can not have an overlapped structure passed to it (throws invalid command exception)
        self.myMACaddr = win32file.DeviceIoControl(self.myInterface, self.TAP_IOCTL_GET_MAC, None, 16)
        alert("MAC address updated: " + str(self.myMACaddr))
        return self.myMACaddr

    def createInterface(self):
        if self.myGUID == "":
            alert("GUID is empty - the device needs to be identified before calling this function.", "_all")
            return False
        else:
            try:
                return win32file.CreateFile(r'\\.\Global\%s.tap' % self.myGUID,
                                      win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                      win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                      None, win32file.OPEN_EXISTING,
                                      win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED | win32file.FILE_FLAG_NO_BUFFERING,
                                      None)
                                      
            except:
                alert("Failed to create interface to TAP device.", "_all")
                return False
    
    #A function to constantly grab data from the tap device, perform some basic filtering, and enter the results in a queue
    #This function is no longer portable as-is, references to the main queue would need to be removed
    def dataListenerThread(self, mainTaskQueue, MTU):
        #Create local variable class
        local = threading.local()

        #Allocate our read buffer
        local.readBuffer = win32file.AllocateReadBuffer(MTU)
        
        #Create an event to wait on
        local.overlapped = pywintypes.OVERLAPPED()
        local.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        while True:
            try:
                local.readResult = win32file.ReadFile(self.myInterface, local.readBuffer, local.overlapped)
                local.a = win32event.WaitForSingleObject(local.overlapped.hEvent, win32event.INFINITE)
                
                #Diagnostics
                if local.a != win32event.WAIT_OBJECT_0:
                    print("Data Listener Thread: Error while waiting on read completion signal: " + str(local.a))
                
            except:
                print("Device malfunctioned during read operation. Attempting to continue...")
                continue
                    
            #Truncate to the actual data - only for IP Packets
            #TODO: This functionality has been hacked, this needs to be redone to work properly
            if bytes(local.readResult[1][12:14]) == b"\x08\x00" :
                local.dataLen = int.from_bytes(local.readResult[1][16:18], 'big')
                mainTaskQueue.put(bytes(local.readResult[1][14*self.trimEthnHeaders:14+local.dataLen]))
                       
            elif bytes(local.readResult[1][12:14]) == b"\x08\x06":
                local.dataLen = 28       #ARP on IPv4 are always 28 bytes long
                mainTaskQueue.put(bytes(local.readResult[1][14*self.trimEthnHeaders:14+local.dataLen]))
            else:
                alert('Non-IP/ARP packet was discarded. EtherType code: ' + str(bytes(local.readResult[1][12:14])))
    
    def dataWriterThread(self, toWriteQueue):
        #Create local variable class
        local = threading.local()
        
        #Create an event to wait on
        local.overlapped = pywintypes.OVERLAPPED()
        local.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
    
        while True:
            #Block and wait for data
            if self.trimEthnHeaders:
                #Add Ethernet header back onto the packet (since it was removed)
                #TODO: this function needs to perform a lookup of the MAC address
                local.remoteMACaddr = b"\xc4\x15\x53\xb3\x04\x33"
                local.writeData = self.myMACaddr + local.remoteMACaddr + b"\x08\x00" + toWriteQueue.get(block=True)
            else:
                local.writeData = toWriteQueue.get(block=True)
            
            #alert('Injecting packet on adapter')
            win32file.WriteFile(self.myInterface, local.writeData, local.overlapped)
            win32event.WaitForSingleObject(local.overlapped.hEvent, win32event.INFINITE)

            
myTap = tuntapWin(True)
alert("Tuntap device initialized, interface created.", "_all")
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
client.bind(('0.0.0.0', 51423))
#client.setblocking(False)
client.sendto(MAGIC, server)

connected = False
alert("Client socket created");


def reading_function(mainTaskQueue, client):
    while True:
        data = mainTaskQueue.get(block=True)
        client.sendto(data, server)

reading_thread = threading.Thread(target=reading_function, args=(mainTaskQueue, client), daemon = True)
reading_thread.start()

while True:
    #r = select([client], [], [])[0]
    #print(r)    
    #if client not in r:
    #    continue
    try:
        data, peer = client.recvfrom(PACKET_SIZE)
        if data == MAGIC and not connected:
            connected = True
            alert("Connected to server: {}".format(server))
        elif data and connected:
            myTap.writeDataQueue.put(data)
            alert("Recived server data. Write to TAP.")
        else:
            alert("Trash data from server")
    except socket.error as e:
        pass
