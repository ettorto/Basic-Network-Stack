from scapy.all import *

# Define the custom message
custom_message = "Hello, this is the os project test!"


# Craft the ICMP Echo Request packet with the custom message
packet = IP(dst="192.0.2.7")/ICMP()/custom_message

send(packet)
