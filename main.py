import socket
import dpkt
import pyshark
import networkx as nx
import pandas as pd
import matplotlib.pyplot as plt


pcapOP = 'wlan.pcap'

def getPackets(pcap):
    packets = [] 
    timestamp = []

    with open(pcap, 'rb') as f:
        pcap = dpkt.pcap.Reader(f) 
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if not hasattr(eth.data, 'src'):
                    continue

                ip = eth.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                packets.append((src, dst))
                timestamp.append(ts)
            except KeyboardInterrupt:
                sys.exit(0)
            except:
                continue
    return packets, timestamp


def visualMap(packets):
    for src_ip, dst_ip in packets:
         
    
    
    
    


def main():
    packets, timestamps, src, dst  = getPackets(pcapOP)
    visualMap(packets)
    

    '''
    for src_ip, dst_ip in packets:
        print(f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n")
    '''












if __name__ == "__main__":
    main()

