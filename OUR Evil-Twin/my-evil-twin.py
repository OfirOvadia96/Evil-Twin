from scapy.all import * 
import os
from threading import Thread



interFace = "" # indentfied Network Card
ac_point_list = [] #access point list



def changeToMonitorMode(iface):
    os.system("sudo ifconfig " + iface + " down")
    os.system("sudo iwconfig " + iface +" mode monitor")
    os.system("sudo ifconfig " + iface +" up")

    os.system("iwconfig") #show as the mode changed

def changeToManagedMode(iface):
    os.system("sudo ifconfig " + iface + " down")
    os.system("sudo iwconfig " + iface + " mode Managed")
    os.system("sudo ifconfig " + iface +" up")
    os.system("clear")
    os.system("iwconfig") #show as the mode changed


def packetHandler(packet):
    # if packet has 802.11 layer (Dot11 = 802.11)
    # if mac adder is not already in out list of access point (addr2 = MAC address)
    # Beacon - announce the presence of a wireless LAN
    if packet.haslayer(Dot11Beacon) and packet.addr2 not in ac_point_list:
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        ac_point_list.append(packet.addr2) # BSSID
        ac_point_list.append(packet.info) #append SSID
        ac_point_list.append(channel)
        print("addr2(MAC): ", packet.addr2, "   info(SSID): " ,packet.info, "   channel: ", channel)



def packetUsers(packet):
    pass



def change_channel(iface):
    ch = 1
    #---------------Need to set timer in this loop ---------------
    while True:
        os.system("sudo iwconfig " + iface +  " channel " + str(ch))
        # switch channel from 1 to 14 each 5s
        ch = ch % 14 + 1
        time.sleep(5)


def main():
    os.system("iwconfig") #to see our interfaces we have
    global interFace
    interFace = input("please insert iface: ")
    changeToMonitorMode(interFace)

    #Scanning access point Wifi
    print("scanning for Wifi...")
    channel_changer = Thread(target=change_channel(interFace))
    channel_changer.daemon = True
    channel_changer.start()
    sniff(iface=interFace ,prn = packetHandler, timeout = 80)


    if len(ac_point_list) == 0: #if we doesn't found any access point
        print("doesn't found access points")
        sys.exit() # end script

    # Scanning clients
    #sniff(iface=interFace, prn = packetUsers , timeout=80)

    changeToManagedMode(interFace)



if __name__ == "__main__":
    main()