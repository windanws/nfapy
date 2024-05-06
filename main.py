import socket
import dpkt
import networkx as nx
import pandas as pd
import argparse
from pyvis.network import Network


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



def dataFrameNetwork(packets, save):
    df = pd.DataFrame(packets, columns=['Source IP', 'Destination IP']) 
    
    if save == True:
        df.to_csv("pcaptoCSV.csv", index=False)

    return df 
    


def graphGen(df, sampleAmount):

    print("=== Processing Graph===")
    df = df.sample(n=sampleAmount) 
    G = nx.from_pandas_edgelist(df, source='Source IP', target='Destination IP', create_using=nx.DiGraph())
    nx.draw_networkx(G)
    nt = Network("720px", "100%")
    nt.from_nx(G)
    nt.show("nx.html", notebook=False)


     

def printPackets(packets):
    for src_ip, dst_ip in packets:
        print(f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n")
    


def getArgs(argv=None):
    parser = argparse.ArgumentParser(description = "NFApy - Network Forensic Analytical Tool")
    parser.add_argument("filename", help = "Specify PCAP file")

    parser.add_argument("-v", "--version", action="version", version="Nfapy 1.0")
    parser.add_argument("-s", "--save", action="store_true", help = "Save PCAP file to CSV")
    parser.add_argument("-g", "--graph", action="store_true", help = "Create Network Graph from PCAP File")
    
    parser.add_argument("-n", "--number", nargs="?", const=100, default=100, type=int, help = "Number of Nodes in Graph")


    return parser.parse_args(argv)



def main():
    args = getArgs()

    packets, timestamps = getPackets(args.filename)
   
    if args.save == True:
        df = dataFrameNetwork(packets, True)
    else:
        df = dataFrameNetwork(packets, False)


    if args.graph == True:
        graphGen(df, args.number)
    else:
        pass







if __name__ == "__main__":
    main()
