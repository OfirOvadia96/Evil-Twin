from scapy.all import *
from threading import *
import os
import time

# globals variables
detected = False  # found an attampet to attack
# a key-value dictionary that contains the mac adress and the channel of all the fake APs
imposters_dict = {}  # [mac, ch], [mac, ch]...

network_adapter = ""

# Sniff packets
ap_list = []


def switchToMonitorMode():
    os.system('sudo ifconfig %s down' % network_adapter)
    os.system('sudo iwconfig %s mode monitor' % network_adapter)
    os.system('sudo ifconfig %s up' % network_adapter)


def PacketHandlerAP(packet):
    global ap_list

    # if packet has 802.11 layer (Becoin) and filter type & subtype of packets
    if packet.haslayer(Dot11):
        if (packet.type == 0 and packet.subtype == 8):
            if [packet.addr2, packet.info, int(ord(packet[Dot11Elt:3].info))] not in ap_list:
                #AP, SSID, Channel
                ap_list.append([packet.addr2, packet.info,
                               int(ord(packet[Dot11Elt:3].info))])
                # print("Access Point MAC: %s | with SSID: %s  | Channel: %d" %(packet.addr2,packet.info, int(ord(packet[Dot11Elt:3].info))))


def WLANScaning():
    global network_adapter
    print("Scanning for access points...")
    # Scan for 2 minutes
    sniff(iface=network_adapter, prn=PacketHandlerAP, timeout=30)
    num = len(ap_list)
    for x in range(num):
        # Num of AP, SSID, AP MAC
        print(x, ap_list[x][1], ap_list[x][0])

def fakeAPsScanning():
    global network_adapter
    print("Scanning for access points...")
    # Scan for 2 minutes
    sniff(iface=network_adapter, prn=PacketHandlerAP, timeout=30)
    num = len(ap_list)
    for x in range(num):
        # Num of AP, SSID, AP MAC
        print(x, ap_list[x][1], ap_list[x][0])

def setChannel(channel):
    os.system('iwconfig %s channel %d' % (network_adapter, channel))

# activates the defense mode to prevent an Evil Twin attack


def activateDefenseMode(sniff_network_adapter):
    global ap_list
    global network_adapter
    network_adapter = sniff_network_adapter

    switchToMonitorMode()
    # scanning for APs
    WLANScaning()
    network_index = int(input("Please enter the index of the newtork you want to protect: "))
    print("*Defense against Evil Twin attack has been activated*")
    # stores the ssid of the network
    ssid_to_protect = ap_list[network_index][1]
    # stores the original mac adress of the network
    original_mac_to_protect = ap_list[network_index][0]
    while True:
        ap_list.clear()
        fakeAPsScanning()
        # how many APs have been found
        num_of_found_APs = len(ap_list)
        if num_of_found_APs > 1:
            checkForImposters(num_of_found_APs, ssid_to_protect,
                              original_mac_to_protect)
        else:
            print("No threats were found")


# The function checks if there is any AP with the same ssid but with other mac address
def checkForImposters(num_of_found_APs, ssid_to_protect, original_mac_to_protect):
    global detected
    global imposters_dict

    # itterates over all the APs
    for i in range(num_of_found_APs):
        current_mac = ap_list[i][0]
        current_ssid = ap_list[i][1]
        # checks if the current AP is an imposter
        if (ssid_to_protect == current_ssid) and (original_mac_to_protect != current_mac):
            detected = True
            current_channel = ap_list[i][2]
            imposters_dict[current_mac] = current_channel
            print("watch out! " + current_mac + " is an imposter")

    # call to the iron dome function if any imposter was found
    if detected == True:
        # elimiate all the imposters
        time.sleep(4)
        ironDome()
    else:
        print("No threats were found")

# The function attacks all the imposters to disonnect thier AP


def ironDome():
    # itterates over all the imposters
    for mac_of_target_AP, channel_of_target_AP in imposters_dict.items():
        setChannel(channel_of_target_AP)
        print("Attacking the fake AP with the following mac: " + mac_of_target_AP)
        for y in range(10000):
            # removed addr1
            dot11 = Dot11(addr2=mac_of_target_AP, addr3=mac_of_target_AP)
            packet = RadioTap()/dot11/Dot11Deauth()
            sendp(packet, iface=network_adapter, count=30, inter=.001)

