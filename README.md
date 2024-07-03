import pyshark
import json
import os

input_file = "smb.pcap"

print ("input file = ", os.path.abspath(input_file))
print ("file size= ", os.path.getsize(input_file))

print ("---------------------------Metadata----------------------------")

capture_file = pyshark.FileCapture("smb.pcap", display_filter='smb2.cmd == 8 || smb2.cmd == 9')

metadata= []

count = 1

for packet in capture_file:

    metadata_temp = {

                    "Src IP": packet.ip.src,
                    "Src port": packet.tcp.srcport,
                    "Dst IP": packet.ip.dst,
                    "Dst port": packet.tcp.dstport,
                 
                }
    print ("packet {} :".format(count), metadata_temp)
    count += 1
    metadata.append(metadata_temp)
  
capture_file.close()

with open("metasdata.json", 'w') as output_file:
        json.dump(metadata, output_file, indent=4)






Imports and File Setup:
These are standard Python libraries (os for file operations, .json for JSON file handling) and pyshark for packet analysis.

Input File Information:
This section prints the absolute path and size of the input of .pcap file.

Packet Capture and Metadata Extraction:
pyshark.FileCapture initializes a capture object for reading packets from smb.pcap and filters packets where SMBv2 commands (smb2.cmd) are either 8 or 9.
For each packet matching the filter, metadata such as source IP, source port, destination IP, and destination port are extracted and stored in metadata_temp.
Each metadata_temp dictionary is printed and added to the metadata list.

Closing the Capture File:
Ensures proper closure of the capture file once all packets have been processed.

Writing Metadata to JSON File:
Opens metasdata.json in write mode and writes the extracted metadata into the file in JSON format with an indentation level of 4 spaces.


Explanation:

This script reads a .pcap file containing captured network packets.
It filters packets related to SMBv2 command 8 and 9.
For each packet that matches the filter, it extracts key metadata: source IP, source port, destination IP, and destination port.
It prints each packet's metadata to the console and stores it in a list.
Finally, it generates all collected metadata into a JSON file named metasdata.json.
 




