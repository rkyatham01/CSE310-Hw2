import dpkt
import sys
import socket
from collections import deque
#Creating a dictionary as a shortcut to the flags
tcpFlagDict = {'FIN': dpkt.tcp.TH_FIN,'SYN': dpkt.tcp.TH_SYN,'RST': dpkt.tcp.TH_RST,
               'PUSH': dpkt.tcp.TH_PUSH,'ACK': dpkt.tcp.TH_ACK}

class NetworkFlow: #class for Flow information
    def __init__(self,srcIP,srcPort,dstIp, dstPort,initTime, finishTime, transacLen, throughput, sendToRecFlow1, recToSendFlow1, sendToRecFlow2, recToSendFlow2, packageArrSendToRec, packageArrRecToSend, transacAvgTime, congWindowArr, recToSenderAckArr, sendToReceiverSeqArr):
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
        self.packageArrSendToRec = packageArrSendToRec
        self.packageArrRecToSend = packageArrRecToSend
        self.transacAvgTime = transacAvgTime
        self.congWindowArr = congWindowArr
        self.recToSenderAckArr = recToSenderAckArr
        self.sendToReceiverSeqArr = sendToReceiverSeqArr

class Transaction: #Class for Transactions within the Flows
    def __init__(self, transactionNum, seqNumb, AckNum, RecWin):
        self.transactionNum = transactionNum
        self.seqNumb = seqNumb
        self.AckNum = AckNum
        self.RecWin = RecWin

class Packet: #Class for packets
    def __init__(self, time, senderRecIp, portNum, packetLen):
        self.time = time
        self.senderRecIp = senderRecIp
        self.portNum = portNum
        self.packetLen = packetLen

def printFunction(finalFlows): #prints all the information that we extracted from the PCAP packet
    flowNum = 1
    for key,flow in finalFlows.items():
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
        print(f'  Congestion Window Sizes : {flow.congWindowArr}')
        print("-----------------------------------------------------")
        flowNum += 1

def pcap_parser():
    #path = input("Enter the file path of the pcap file: ")
    #Hard coded path for now to test
    # while path[-5:] != ".pcap":
    #     path = input("Incorrect file path enterred, please enter correct file path: ")
    # print()
    file = open("assignment2.pcap", 'rb') #opening the file in read byte mode
    pcap = dpkt.pcap.Reader(file) #Reader class that takes a file object and reads from it
   # finalFlows = [] #gonna contain all the flows to print at the end / contains object NetworkFlow after each flow finishes
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
        
        # if (tcp.flags and (tcp.flags & tcpFlagDict["SYN"]) and (tcp.flags & tcpFlagDict["ACK"])): #Receiver to Sender communication
        backwardTup = (dstIp, dstPort, srcIP, srcPort)

        if (tcp.flags and (tcp.flags & tcpFlagDict["SYN"])): #Sender to Receiver
            if forwardTup in flowTracker or backwardTup in flowTracker: #flow already existing / edge case
                continue
            else:
                flowTracker[forwardTup] = NetworkFlow(srcIP, srcPort, dstIp, dstPort, ts, 0, 0, 0, None, None, None, None, [], [], 0, [], [], []) #Just for initializing F : forward B : backward
        elif (tcp.flags and (tcp.flags & tcpFlagDict["FIN"])): #just calculate the flow time finish
            #if forwardTup in flowTracker:
                #finalFlows.append(flow) #Appending the flow so can print later all the information stored of the transactions
            pass
        else:
            if srcIP == '130.245.145.12': #hard coded ip
                if forwardTup in flowTracker: #Transaction from sender to receiver is being done
                    flow = flowTracker[forwardTup] 
                    if flowTracker[forwardTup].sendToRecFlow1 == None: #Transac 1 Sender -> Receiver
                        transacObj = Transaction(1, tcpSeq, tcpAck, tcpRecWin)
                        flowTracker[forwardTup].sendToRecFlow1 = transacObj #Resetting as this object
                        flow.transacAvgTime = ts
                    elif flowTracker[forwardTup].sendToRecFlow2 == None and (tcpSeq != flowTracker[forwardTup].sendToRecFlow1.seqNumb): #Transac 2 Sender -> Receiver
                        transacObj2 = Transaction(2, tcpSeq, tcpAck, tcpRecWin)
                        flowTracker[forwardTup].sendToRecFlow2 = transacObj2 #Resetting as this object
                flow.sendToReceiverSeqArr.append(tcpSeq) #appending tcp Sequence numbers for the triple ack part
                newPacket = Packet(ts,'130.245.145.12', srcPort, len(tcp.data)) #Creates a new packet coming in from sender
                flow.packageArrSendToRec.append(newPacket) #adding packages from sender to receiver
            #Adding throughput no matter what
            if srcIP == '128.208.2.198':
                if backwardTup in flowTracker: #For receiver to sender 
                    flow = flowTracker[backwardTup]
                    if flowTracker[backwardTup].recToSendFlow1 == None: #Transac 1 Receiver -> Sender
                        if tcpSeq == flow.sendToRecFlow1.AckNum:
                            transacObj = Transaction(1, tcpSeq, tcpAck, tcpRecWin)
                            flowTracker[backwardTup].recToSendFlow1 = transacObj #Resetting as this object
                        flow.transacAvgTime = ts - flow.transacAvgTime #calculating the rtt
                    
                    elif flowTracker[backwardTup].recToSendFlow2 == None: #Transac 2 Receiver -> Sender
                        if tcpSeq == flow.sendToRecFlow2.AckNum:
                            transacObj2 = Transaction(2, tcpSeq, tcpAck, tcpRecWin)
                            flowTracker[backwardTup].recToSendFlow2 = transacObj2 #Resetting as this object
                flow.recToSenderAckArr.append(tcpAck) #Adding the ack for the triple ack part
                newPacket2 = Packet(ts,'128.208.2.198',srcPort, len(tcp.data)) #Creates a new packet coming in from sender
                flow.packageArrRecToSend.append(newPacket2) #adding packages from receiver to sender
            flow.finishTime = ts #updating final time in the Flow after last acknowledgment
            flow.throughput += len(tcp)
            
    for key,flow in flowTracker.items(): #For Calculating Congestion Window
        tempCongWindows = []
        origPackageArr = flow.packageArrSendToRec
        firstPacket = origPackageArr[0]
        firstPacketsTime = firstPacket.time #extracts the first packets time
        rtt = flow.transacAvgTime
        endOfCongWind = firstPacketsTime + rtt #calculating end of congestion window
        congWin = 0 #congestion window
        for packages in origPackageArr:
            if packages.time < endOfCongWind:
                congWin += 1
            else:
                endOfCongWind += rtt
                origPackageArr = origPackageArr[congWin:] #slicing it off
                tempCongWindows.append(congWin)                    
                congWin = 0
                if len(tempCongWindows) == 3:
                    flow.congWindowArr = tempCongWindows #setting congestion window to its respective flow
                    break
        
    for key,flow in flowTracker.items(): #For Calculating # of times of retransmission due to timeout and triple duplicate ack
        arrForTripleAcks = set()
        retransmissionCount = 0
        recToSenderPacketsArr = flow.recToSenderAckArr
        que = deque()
        for ack in recToSenderPacketsArr:
            que.append(ack)
            if len(que) == 3:
                if que[-1] == que[-2] == que[-3]: #if found a triple ack in receivers to senders acks
                    arrForTripleAcks.add(que[-1]) #append the ack
                que.popleft()
            
        for seq in flow.sendToReceiverSeqArr:
            if seq in arrForTripleAcks:
                retransmissionCount += 1
        print("Retransmission due to triple Ack", retransmissionCount)

    for key,flow in flowTracker.items(): #For Calculating # of times of timeouts
        sendToRecPackets = flow.sendToReceiverSeqArr
        recToSendPackets = flow.packageArrRecToSend
        rtt = flow.transacAvgTime
        print(len(sendToRecPackets))
        print(len(recToSendPackets))


    #printFunction(flowTracker)

if __name__ == "__main__":
    pcap_parser()