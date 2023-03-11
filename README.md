Rishith Kyatham

CSE310 Coding Assignment 2 ReadMe

Pcap Analysis :
We used the TCP PCAP Analysis Tool to analyze Pcap files with a python package that I wrote that is named analysis_pcap_tcp.py.

Dependencies : 
You should use the command pip install dpkt to install the dpkt package to run the analysis_pcap_tcp.py python file as this is required. 

How to run it :
The function pcap_parser() in my code asks for a path input. Once the path input is given, it reads all the information about the flows, transactions,  sequence_number, Ack numbers, throughput, congestion window sizes, timeout, triple acks, total transmission, other transmissions, and much more information in a neatly organized way.
Ensure the path is correct and the Pcap file is in the same directory as the python file.
To run my python file, type the command py analysis_pcap_tcp.py or python analysis_pcap_tcp.py
Input - Path File
Output - Sample data for a Pcap file
Make sure it is a .pcap file or the program will prompt you to re-enter until the requirement is satisfied
How the program works is it loops through the Pcap file detecting packets that go from sender to receiver and receiver to sender. It will initially set up the 3-way handshake and continue from there with the flow until the Fin flag.
You can either input more PCAP files to analyze more files or simply rerun the code so it prompts you to enter a different path to run the program.
