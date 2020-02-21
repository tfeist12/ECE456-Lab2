# ECE456-Lab2
Second Programming assignment for ECE Computer Networks at Colorado State University

Tyler Feist
Lab #2
ECE 456

UDP Datagram sender and receiver program

Instructions:

the key used for encryption/decryption must be put in key.txt

Sender:
1) navigate to the directory with sender.py in it via the command line
2) ensure the directory also contains helper.py and L1.py
3) sender.py requires 6 command line arguments: inFileName, sourceIP, destIP, sourcePort, DestPort, and datagramFileName 
4) run "python sender.py <inFileName> <sourceIP> <destIP> <sourcePort> <DestPort> <datagramFileName>"
5) the script will read data from <inFileName>, encrypt it, build a pseudo header and a UDP datagram, and write them as bytes to <datagramFileName>
6) the encrypted data is also written to a file named sOut

Receiver:
1) navigate to the directory with receiver.py in it via the command line
2) ensure the directory also contains helper.py and L1.py
3) receiver.py requires 3 command line arguments: sourceIP, destIP, and datagramFileName
4) run "python receiver.py <sourceIP> <destIP> <datagramFileName>"
5) the script will read data from <datagramFileName>, if the checksum is correct it will provide info about the datagram, decrypt the file contained in it and write it as bytes to rOut  
