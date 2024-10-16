import scapy.all as scapy
from scapy.layers import http
import optparse

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-i", "--interface", dest="interface", help="Network interface to listen")  
    (options, arguments) = parseObject.parse_args()
    return options

def packetSniff(interface):

    scapy.sniff(iface=interface,store=False,prn=packetAnalyze)

def packetAnalyze(packet):

    packet.show()

userInput = getUserInput()
packetSniff(userInput.interface)
