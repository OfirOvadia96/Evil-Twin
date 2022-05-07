from scapy.all import * 
import os
from threading import Thread
import time



interface = "" # indentfied Network Card
AP_dict = {} #founded AP
indexTarget = 0



def changeToMonitorMode(iface):
    os.system("sudo ifconfig " + iface + " down")
    os.system("sudo iwconfig " + iface +" mode monitor")
    os.system("sudo ifconfig " + iface +" up")

    os.system("iwconfig") #show as the mode changed

def changeToManagedMode(iface):
    os.system("sudo ifconfig " + iface + " down")
    os.system("sudo iwconfig " + iface + " mode Managed")
    os.system("sudo ifconfig " + iface +" up")
    os.system("iwconfig") #show as the mode changed


def packetHandler(packet):
    global indexTarget
    global AP_dict
    # if packet has 802.11 layer (Dot11 = 802.11)
    # Beacon - announce the presence of a wireless LAN
    if packet.haslayer(Dot11Beacon):
        
        # check if we had this AP already
        flag = False
        for i in AP_dict:
            key_list = AP_dict.get(i)
            if packet.addr2 in key_list:
                flag = True
                break

        # if mac adder is not already in our dictionary of AP (addr2 = MAC address)
        if flag == False:
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            
            ap_point_list = []
            ap_point_list.append(packet.addr2) # BSSID
            ap_point_list.append(packet.info) #append SSID
            ap_point_list.append(channel)
            AP_dict[indexTarget] = ap_point_list
            
            print("index: ", indexTarget,"   addr2(MAC): ", packet.addr2, "   info(SSID): " ,packet.info, "   channel: ", channel)
            indexTarget = indexTarget + 1
        



def packetUsers(packet):
    pass



def change_channel(iface):
    ch = 1
    #---------------Need to set timer in this loop ---------------
    start = time.time()

    while True:
        os.system("sudo iwconfig " + iface +  " channel " + str(ch))
        # switch channel from 1 to 14 each 5s
        ch = ch % 14 + 1
        end = time.time()

        if end-start > 75 : 
            break #end loop

        time.sleep(1)


def changeChannelToAP(iface : str , index : int) -> None:
    global AP_dict
    AP_details = AP_dict.get(index)
    channel_target = AP_details[2] #get the channel
    channel_target_converted = str(channel_target)
    os.system("sudo iwconfig " + iface + " channel " + channel_target_converted)


def main():
    os.system("iwconfig") #to see our interfaces we have
    global interface
    global AP_dict
    interface = input("please insert iface: ")
    os.system("clear")
    changeToMonitorMode(interface)

    #Scanning access point Wifi
    print("scanning for Wifi...")
    channel_changer = Thread(target=change_channel(interface))
    channel_changer.daemon = True
    channel_changer.start()
    sniff(iface=interface ,prn = packetHandler, timeout = 60)


    if len(AP_dict) == 0: #if we doesn't found any access point
        print("doesn't found access points")
        sys.exit() # end script

    convertedChosen = -1
    while True:
        #choose access point
        chosenAP = input("Enter an access point index to attack: ")

        #Check input
        try:
            convertedChosen = int(chosenAP)
        except ValueError:
            print("That's not a number")
            continue

        if convertedChosen in AP_dict:
            break
        
        print("Invalid index")


    changeChannelToAP(interface,convertedChosen)

    # Scanning clients
    print("scanning clients...")
    sniff(iface=interface, prn = packetUsers , timeout=60)

    changeToManagedMode(interface) # change back to default mode


if __name__ == "__main__":
    main()