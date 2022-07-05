import struct
from dataclasses import dataclass
from typing import Tuple

from . import finals
from .device import NetDevice
from .ethernet import EthernetFrame
from .icmp import incoming_ICMP
from .utils import calculate_checksum


@dataclass
class IPv4:
    version: int
    header_length: int
    type_of_service: bytes
    total_length: int
    fragmentation_data: bytes
    ttl: int
    protocol: int
    header_checksum: int
    source_address: bytes
    destination_address: bytes
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes | int] = struct.unpack("!BsH4sBBh4s4s", data[:20])
        self.version = header[0] >> 4
        self.header_length = header[0] & (0x0F)*4
        self.type_of_service = header[1]
        self.total_length = header[2]
        self.fragmentation_data = header[3]
        self.ttl = header[4]
        self.protocol = header[5]
        self.header_checksum = header[6]
        self.source_address = header[7]
        self.destination_address = header[8]
        self.payload = data[20:]

    def to_struct(self) -> bytes:
        version_length: bytes = (((self.version & (0x0F)) << 4) +
                                 ((self.header_length//4) & (0x0F))).to_bytes(1, 'big')
        total_length: bytes = self.total_length.to_bytes(2, 'big')
        ttl: bytes = self.ttl.to_bytes(1, 'big')
        protocol: bytes = self.protocol.to_bytes(1, 'big')
        checksum: bytes = self.header_checksum.to_bytes(2, 'big')
        return struct.pack('!ss2s4sss2s4s4s',
                           version_length, self.type_of_service, total_length,
                           self.fragmentation_data, ttl, protocol, checksum,
                           self.source_address, self.destination_address
                           )+self.payload


def incoming_ipv4(frame: EthernetFrame, device: NetDevice) -> None:
    ip_header: IPv4 = IPv4(frame.payload)
    if (ip_header.version != 4 or ip_header.header_length < 5 or
            ip_header.ttl == 0 or calculate_checksum(frame.payload) != 0):
        print('Incorrect datagram')
        return
    if ip_header.protocol == finals.ICMPV4:
        incoming_ICMP(frame, device)
        return
    print('Unknown IP datagram')
