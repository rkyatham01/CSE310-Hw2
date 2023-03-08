import dpkt
import sys
import socket

#Creating a dictionary as a shortcut to the flags
tcpFlagDict = {'FIN': dpkt.tcp.TH_FIN,'SYN': dpkt.tcp.TH_SYN,'RST': dpkt.tcp.TH_RST,
               'PUSH': dpkt.tcp.TH_PUSH,'ACK': dpkt.tcp.TH_ACK}

class NetworkFlow: #class for Flow information
    def __init__(self,srcIP,srcPort,dstIp, dstPort,initTime, finishTime, transacLen, throughput, sendToRecFlow1, recToSendFlow1, sendToRecFlow2, recToSendFlow2):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIp = dstIp
        self.dstPort = dstPort
        self.initTime = initTime
        self.finishTime = finishTime
        self.transactionLen = transacLen
        self.throughput = throughput
        self.sendToRecFlow1 = sendToRecFlow1 #first transaction Sender to Receiver
        self.recToSendFlow1 = recToSendFlow1 #first transaction Receiver to Sender
        self.sendToRecFlow2 = sendToRecFlow2 #second transaction Sender to Receiver
        self.recToSendFlow2 = recToSendFlow2 #second transaction Receiver to Sender

class Transaction: #Class for Transactions within the Flows
    def __init__(self, transactionNum, seqNumb, AckNum, RecWin):
        self.transactionNum = transactionNum
        self.seqNumb = seqNumb
        self.AckNum = AckNum
        self.RecWin = RecWin

def printFunction(finalFlows): #prints all the information that we extracted from the PCAP packet
    flowNum = 1
    for flow in finalFlows:
        transac1SendToRec = flow.sendToRecFlow1
        transac1RecToSend = flow.recToSendFlow1
        transac2SendToRec = flow.sendToRecFlow2
        transac2RecToSend = flow.recToSendFlow2

        print(f'TCP Flow # {flowNum}')
        print(f'  SrcIP: {flow.srcIP}, DstIP:{flow.dstIp}, SrcPort:{flow.srcPort}, DstPort:{flow.dstPort}')
        print("  Transaction 1")
        print(f'    Sender -> Receiver     Sequence_Number:{transac1SendToRec.seqNumb}  ACK:{transac1SendToRec.AckNum}  Receive_Window_Size:{transac1SendToRec.RecWin}')
        print(f'    Receiver -> Sender     Sequence_Number:{transac1RecToSend.seqNumb}  ACK:{transac1RecToSend.AckNum}  Receive_Window_Size:{transac1RecToSend.RecWin}')
        print("  Transaction 2")
        print(f'    Sender -> Receiver     Sequence_Number:{transac2SendToRec.seqNumb}  ACK:{transac2SendToRec.AckNum}  Receive_Window_Size:{transac2SendToRec.RecWin}')
        print(f'    Receiver -> Sender     Sequence_Number:{transac2RecToSend.seqNumb}  ACK:{transac2RecToSend.AckNum}  Receive_Window_Size:{transac2RecToSend.RecWin}')
        timeDiff = flow.finishTime - flow.initTime #calculating time difference
        throughput = flow.throughput / timeDiff #calculating throughput
        print(f'  Throughput = {throughput} bytes/second')
        print("---------------------------------------------------")
        flowNum += 1

def pcap_parser():
    #path = input("Enter the file path of the pcap file: ")
    #Hard coded path for now to test
    path = "c:\\Users\\Rishith\\OneDrive\\Documents\\CSE310-Hw2\\assignment2.pcap"
    while path[-5:] != ".pcap":
        path = input("Incorrect file path enterred, please enter correct file path: ")
    print()
    file = open(path, 'rb') #opening the file in read byte mode
    pcap = dpkt.pcap.Reader(file) #Reader class that takes a file object and reads from it
    finalFlows = [] #gonna contain all the flows to print at the end / contains object NetworkFlow after each flow finishes
    flowTracker = {} #key : (tuple of flow) Value : information about Flow
    for ts, buff in pcap: #accessing each packet contained in the pcap object / ts : time stamp / #buff : buffer (packet data length would be len(buff)) (contains the data)
        eth = dpkt.ethernet.Ethernet(buff) #parses and decodes the packet data into a eth object / more usable form / Now that the IP and TCP layer information has been decoded, we can access it
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
        forwardTup = (srcIP, srcPort, dstIp, dstPort)
        tcpSeq = tcp.seq  # tcp sequence number
        tcpAck = tcp.ack  # tcp ack number
        tcpRecWin = tcp.win  # tcp window value
        
        if (tcp.flags and (tcp.flags & tcpFlagDict["SYN"]) and (tcp.flags & tcpFlagDict["ACK"])): #Receiver to Sender communication
            backwardTup = (dstIp, dstPort, srcIP, srcPort)
            flow = flowTracker[forwardTup] 
            if backwardTup in flowTracker:
                if flowTracker[forwardTup].recToSendFlow1 == None: #Flow 1 Sender -> Receiver
                    transacObj = Transaction(1, tcpSeq, tcpAck, tcpRecWin)
                    flowTracker[forwardTup].recToSendFlow1 = transacObj #Resetting as this object
                elif flowTracker[forwardTup].recToSendFlow2 == None: #Flow 2 Sender -> Receiver
                    transacObj2 = Transaction(2, tcpSeq, tcpAck, tcpRecWin)
                    flowTracker[forwardTup].recToSendFlow2 = transacObj2 #Resetting as this object
                    flow.finishTime = ts #updating final time in the Flow after last acknowledgment
            flow += flow.throughput
                
        elif (tcp.flags and (tcp.flags & tcpFlagDict["SYN"])): #Sender to Receiver
            if forwardTup in flowTracker: #flow already existing / edge case
                continue
            else:
                flowTracker[forwardTup] = NetworkFlow(srcIP, srcPort, dstIp, dstPort, ts, 0, 0, 0, None, None, None, None) #Just for initializing F : forward B : backward

        elif (tcp.flags and (tcp.flags & tcpFlagDict["FIN"])): #just calculate the flow time finish
            if forwardTup in flowTracker:
                finalFlows.append(flow) #Appending the flow so can print later all the information stored of the transactions
        else:
            if forwardTup in flowTracker: #Transaction from sender to receiver is being done
                flow = flowTracker[forwardTup] 
                if flowTracker[forwardTup].sendToRecFlow1 == None: #Flow 1 Sender -> Receiver
                    transacObj = Transaction(1, tcpSeq, tcpAck, tcpRecWin)
                    flowTracker[forwardTup].sendToRecFlow1 = transacObj #Resetting as this object
                elif flowTracker[forwardTup].sendToRecFlow2 == None: #Flow 2 Sender -> Receiver
                    transacObj2 = Transaction(2, tcpSeq, tcpAck, tcpRecWin)
                    flowTracker[forwardTup].sendToRecFlow1 = transacObj2 #Resetting as this object
                    
                #Adding throughput no matter what
                flow += flow.throughput
        printFunction(finalFlows)

if __name__ == "__main__":
    pcap_parser()