import dpkt
import sys
import socket


#Creating a dictionary as a shortcut to the flags
tcpFlagDict = {'FIN': dpkt.tcp.TH_FIN,'SYN': dpkt.tcp.TH_SYN,'RST': dpkt.tcp.TH_RST,
               'PUSH': dpkt.tcp.TH_PUSH,'ACK': dpkt.tcp.TH_ACK}

def pcap_parser():
    #path = input("Enter the file path of the pcap file: ")
    #Hard coded path for now to test
    path = "c:\\Users\\Rishith\\OneDrive\\Documents\\CSE310-Hw2\\assignment2.pcap"
    while path[-5:] != ".pcap":
        path = input("Incorrect file path enterred, please enter correct file path: ")
    print()
    file = open(path, 'rb') #opening the file in read byte mode
    pcap = dpkt.pcap.Reader(file) #Reader class that takes a file object and reads from it
    
    throughputDict = {} #mapping for throughput
    rtt = {} #total amount of time
    initialRtt = {} #intitial times of the RTT
    
    for ts, buff in pcap: #accessing each packet contained in the pcap object
        #ts : time stamp
        #buff : buffer (packet data length would be len(buff)) (contains the data)
        eth = dpkt.ethernet.Ethernet(buff) #parses and decodes the packet data into a eth object / more usable form
        #Now that the IP and TCP layer information has been decoded, we can access it
        #pk.data is the IP object and pk.data.data is the TCP object
        ip = eth.data #can obtain the ip object from eth object
        tcp = eth.data.data #can obtain the tcp object from ip object
        #Now can access the tcp.sport and tcp.dport (source and destination ports of the TCP header)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue #we only care about IP packets
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue #Checking whether its a TCP connection or not
        srcIP = socket.inet_ntop(socket.AF_INET, ip.src) #converts IP address in packed binary format to string format
        srcPort = tcp.sport #Extracts source Port address from the packet
        dstIp = socket.inet_ntop(socket.AF_INET, ip.dst) #converts IP address in packed binary format to string format
        dstPort = tcp.dport #Extracts source Dest address from the packet
        #tcp.flags have the status
        if (tcp.flags and (tcp.flags & tcpFlagDict["SYN"]) and (tcp.flags & tcpFlagDict["ACK"])): #if it contains both SYN AND ACK flags
            print("contains both ACK and SYN")
        elif (tcp.flags and (tcp.flags & tcpFlagDict["SYN"])): #if it only contains SYN flag
            print("contains only SYN")
        elif (tcp.flags and (tcp.flags & tcpFlagDict["FIN"])):
           


if __name__ == "__main__":
    pcap_parser()