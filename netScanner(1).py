import scapy
import optparse

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-i", "--ipaddress", dest="ipAddress", help="target IP address to scan")
    return parseObject.parse_args()

def scanNetwork(ipAddress):

    arpRequestPacket = scapy.ARP(pdst=ipAddress)
    broadcastPacket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcastPacket/arpRequestPacket
    (answered, unanswered) = scapy.srp(combined, timeout=1)
    answered.summary()

print("\n------NET SCANNER-----\n")
(userInput, arguments) = getUserInput()
if not userInput:
    print("\nEnter IP address")
scanNetwork(userInput.ipAddress)

