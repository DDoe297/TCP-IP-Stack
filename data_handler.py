from . import finals
from .arp import incoming_arp
from .device import NetDevice
from .ethernet import EthernetFrame
from .ipv4 import incoming_ipv4


def handler(device: NetDevice):
    while True:
        data: bytes = device.socket.recv(1514)
        frame: EthernetFrame = EthernetFrame(data)
        if frame.protocol == finals.ETH_ARP:
            if reply := incoming_arp(frame, device):
                device.socket.send(reply.to_struct())
        elif frame.protocol == finals.ETH_IP:
            if reply := incoming_ipv4(frame, device):
                device.socket.send(reply.to_struct())
