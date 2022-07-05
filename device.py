import socket
from typing import Dict, Final

from .arp import ArpTable


class NetDevice:
    def __init__(self, mac_address: int, ip_address: str, interface: str) -> None:
        self.mac_address: Final = int.to_bytes(mac_address, 6, 'big')
        self.ip_address: Final = socket.inet_aton(ip_address)
        self.arp_table: Dict[bytes, bytes] = ArpTable()
        self.socket: socket.socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(3))
        self.socket.bind((interface, 0))

    def update_arp_table(self, mac_address: bytes, ip_address: bytes) -> None:
        self.arp_table[mac_address] = ip_address
        print(self.arp_table)
