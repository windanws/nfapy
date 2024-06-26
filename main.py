#!/usr/bin/python3
#lang: utf-8

import time
import re

import socket
import dpkt
import mmap
import pandas as pd
import networkx as nx
from pyvis.network import Network

import argparse



# Seperating SRC and DST from pcap file
def getPackets(pcap):
    packets = [] 
    timestamp = []

    with open(pcap, 'rb') as f:
        mmapFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
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
        mmapFile.close()

        
    return packets, timestamp



# Creating DataFrame (.CSV)
def dataFrameNetwork(packets, timestamps, save):
    df = pd.DataFrame(packets, columns=['Source IP', 'Destination IP']) 
    df.insert(loc=0, column="Time Stamps", value=timestamps)
    timestr = time.strftime("%d-%m_%H-%M-%S")
    if save:
        df.to_csv(f"{timestr}_nfapyData.csv", index=False)
    else:
        pass

    return df 
    


# Creating Graph
def graphGen(df, sampleAmount, options):
    print("=== Processing Graph===")
    df = df.sample(n=sampleAmount) 
    G = nx.from_pandas_edgelist(df, source='Source IP', target='Destination IP', create_using=nx.DiGraph())
    nt = Network(height = "800px", width = "100%", select_menu=True)
    nt.from_nx(G)
    if options:
        nt.width="70%"
        nt.show_buttons()

    if sampleAmount > 100:
        pos = nx.circular_layout(G, scale=sampleAmount*0.2)
        for node in nt.get_nodes():
            nt.get_node(node)['x']=pos[node][0]
            nt.get_node(node)['y']=-pos[node][1]
            nt.get_node(node)['physics']=False
            nt.get_node(node)['label']=str(node)
        nt.toggle_physics(False)

    nt.show("graph.html", notebook=False)



# Counting Addresses from Specific Address
def countPackets(df, ipAddr):
    matching = df[df.apply(lambda row: ipAddr in row.values, axis=1)]
    if not matching.empty:
        pAmount = len(matching)
        print(f"{ipAddr} Totals - {pAmount}")
    else:
        print("\nNo Match Found\nPlease Ensure the Correct Address is Inputted")



# Listing Out Addresses
def listAddress(df, ipAddr):
    print("=== Matching Beginning ===")
    matching = df[df.apply(lambda row: ipAddr in row.values, axis=1)]
    
    if not matching.empty:
        print("\nFound Matching - Beginning Printing Processs")
        for index, row in matching[['Source IP','Destination IP']].iterrows():
            src_ip = row['Source IP']
        dst_ip = row['Destination IP']
        print(f"Source IP: {src_ip} - Destination IP: {dst_ip}\n")
    else:
        print("\nNo Match Found\nPlease Ensure the Correct Address is Inputted")



def test():
    for src_ip, dst_ip in packets:
        print(f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n")



# Arguments
def getArgs(argv=None):
    parser = argparse.ArgumentParser(description = "NFApy - Network Forensic Analytical Tool")
    parser.add_argument("filename", help = "Specify PCAP file")

    parser.add_argument("-v", "--version", action="version", version="Nfapy 1.0")
    parser.add_argument("-s", "--save", action="store_true", help="Save PCAP file to CSV")
    parser.add_argument("-g", "--graph", action="store_true", help="Create Network Graph from PCAP File")
    parser.add_argument("-o", "--options", action="store_true", help="Show Options in Graph Page") 

    parser.add_argument("-l", "--list", action="store", help="List Address and Associated Addresses")
    parser.add_argument("-c", "--count", action="store", help = "Count Amount of Packetse Related to Specific Address\n Left Empty Will Count Total of the File")
    parser.add_argument("-n", "--number", nargs="?", const=100, default=100, type=int, help = "Number of Nodes in Graph")

    return parser.parse_args(argv)



# Main Function
def main():
    args = getArgs()


    if args.filename.endswith(".pcap"):
        packets, timestamps = getPackets(args.filename)
        df = dataFrameNetwork(packets, timestamps, args.save)
        if args.graph:
            graphGen(df, args.number, args.options)
        elif args.count:
            countPackets(df, args.count)
        elif args.list:
            listAddress(df, args.list)
        else:
            pass
    elif args.filename.endswith(".csv"):
        return
    else:
        print("Invaild File Type \nPlease Use -h to Get More Information")
        pass







if __name__ == "__main__":
    main()
