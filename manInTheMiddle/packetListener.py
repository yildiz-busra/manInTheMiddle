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

    if packet.haslayer(http.HTTPRequest):

        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"[+] HTTP Request >> {url}")   

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            print(f"[+] Data: {load}")

userInput = getUserInput()
packetSniff(userInput.interface)
