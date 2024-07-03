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



