import time
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



def dataFrameNetwork(packets, timestamps, save):
    df = pd.DataFrame(packets, columns=['Source IP', 'Destination IP']) 
    df.insert(loc=0, column="Time Stamps", value=timestamps)
    timestr = time.strftime("%d-%m_%H-%M-%S")
    if save:
        df.to_csv(f"{timestr}_nfapyData.csv", index=False)
    else:
        pass

    return df 
    


def graphGen(df, sampleAmount, options):

    print("=== Processing Graph===")
    df = df.sample(n=sampleAmount) 
    G = nx.from_pandas_edgelist(df, source='Source IP', target='Destination IP', create_using=nx.DiGraph())
    nt = Network(height = "800px", width = "100%", select_menu=True)
    nt.from_nx(G)
    if options:
        nt.width="70%"
        nt.show_buttons()
    nt.show("graph.html", notebook=False)



def printPackets(packets):
    for src_ip, dst_ip in packets:
        print(f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n")
    


def getArgs(argv=None):
    parser = argparse.ArgumentParser(description = "NFApy - Network Forensic Analytical Tool")
    parser.add_argument("filename", help = "Specify PCAP file")

    parser.add_argument("-v", "--version", action="version", version="Nfapy 1.0")
    parser.add_argument("-s", "--save", action="store_true", help = "Save PCAP file to CSV")
    parser.add_argument("-g", "--graph", action="store_true", help = "Create Network Graph from PCAP File")
    parser.add_argument("-o", "--options", action="store_true", help = "Show Options in Graph Page") 

    parser.add_argument("-n", "--number", nargs="?", const=100, default=100, type=int, help = "Number of Nodes in Graph")

    return parser.parse_args(argv)



def main():
    args = getArgs()

    if args.filename.endswith(".pcap"):
        packets, timestamps = getPackets(args.filename)
        df = dataFrameNetwork(packets, timestamps, args.save)
        if args.graph:
            graphGen(df, args.number, args.options)
        else:
            pass
    elif args.filename.endswith(".csv"):
        return
    else:
        print("Invaild File Type \nPlease Use -h to Get More Information")
        pass
    







if __name__ == "__main__":
    main()
