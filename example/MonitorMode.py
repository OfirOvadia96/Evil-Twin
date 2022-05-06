import os

def Change_to_MonitorMode_airmon(iface):
    #Checks which components are working on the wireless network - and kills their processes
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start "+ iface)
    os.system("clear")
    os.system("iwconfig")
    iface = str(iface)+'mon' ##-------------------!!!!! Need to check if it can be assumed that the extension will be !!!!!!!!!!!------------##
    return iface

def Change_back_airmon(iface):
    os.system("sudo airmon-ng stop "+ iface)
    os.system("sudo systemctl start NetworkManager")
    os.system("clear")
    

def Change_to_MonitorMode(iface):
    os.system("sudo ip link set "+ iface + " down")
    os.system("sudo iw "+ iface +" set monitor none")
    os.system("sudo ip link set "+ iface +" up")
    os.system("clear")
    return iface
    

def Change_back(iface):
    os.system("sudo ip link set "+ iface+ " down")
    os.system("sudo iw "+ iface+  " set type managed")
    os.system("sudo ip link set "+ iface+ " up")



