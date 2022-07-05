from .arp import incoming_arp
from .device import NetDevice
from .ethernet import EthernetFrame


def handler(device: NetDevice):
    while True:
        data: bytes = device.socket.recv(1514)
        frame: EthernetFrame = EthernetFrame(data)
        if frame.protocol == 0x806:
            if reply := incoming_arp(frame, device):
                device.socket.send(reply.to_struct())
