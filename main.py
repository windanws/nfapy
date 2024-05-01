import socket
import dpkt
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
            except: continue
    return packets, timestamp



def dataFrameNetwork(packets):
    df = pd.DataFrame(packets, columns=['Source IP', 'Destination IP']) 
    return df 
    


def graphGen(df):
    plt.rcParams['toolbar'] = 'None'
    plt.rcParams['keymap.quit'] = ['ctrl+w']
    print("=== Processing Graph===")
    df = df.sample(n=100) 
    G = nx.from_pandas_edgelist(df, source='Source IP', target='Destination IP', create_using=nx.DiGraph())
    plt.figure("Graph", figsize=(12,8), dpi=100)
    nx.draw_networkx(G)


def printPackets(packets):
    for src_ip, dst_ip in packets:
        print(f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n")
    
    
def main():
    packets, timestamps = getPackets(pcapOP)

    df = dataFrameNetwork(packets)
    graphGen(df)
    plt.show()









if __name__ == "__main__":
    main()
