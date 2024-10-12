import scapy.all as scapy
from scapy_http import http
import optparse

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-i", "--interface", dest="interface", help="Network interface to listen")
    return parseObject.parse_args()

def packetSniff(interface):

    scapy.sniff(iface=interface,store=False,prn=packetAnalyze)

def packetAnalyze(packet):

    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

userInput = getUserInput()
packetSniff(userInput.interface)