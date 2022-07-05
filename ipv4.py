import struct
from dataclasses import dataclass
from typing import Tuple

from . import finals
from .device import NetDevice
from .ethernet import EthernetFrame
from .icmp import incoming_icmp
from .utils import calculate_checksum


@dataclass
class IPv4Datagram:
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
        header: Tuple[bytes | int] = struct.unpack("!BsH4sBBH4s4s", data[:20])
        self.version = header[0] >> 4
        self.header_length = header[0] & (0x0F)
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
                                 ((self.header_length) & (0x0F))).to_bytes(1, 'big')
        print(version_length.hex())
        total_length: bytes = self.total_length.to_bytes(2, 'big')
        ttl: bytes = self.ttl.to_bytes(1, 'big')
        protocol: bytes = self.protocol.to_bytes(1, 'big')
        checksum: bytes = self.header_checksum.to_bytes(2, 'big')
        return struct.pack('!ss2s4sss2s4s4s',
                           version_length, self.type_of_service, total_length,
                           self.fragmentation_data, ttl, protocol, checksum,
                           self.source_address, self.destination_address
                           )

    def to_struct_with_payload(self) -> bytes:
        return self.to_struct()+self.payload


def incoming_ipv4(frame: EthernetFrame, device: NetDevice) -> EthernetFrame | None:
    ip_datagram: IPv4Datagram = IPv4Datagram(frame.payload)
    if (ip_datagram.version != 4 or ip_datagram.header_length < 5 or
            ip_datagram.ttl == 0 or calculate_checksum(frame.payload[:20]) != 0):
        print('Incorrect datagram')
        return
    if ip_datagram.protocol == finals.ICMPV4:
        reply: bytes | None = incoming_icmp(ip_datagram.payload)
        if reply:
            ip_datagram.payload = reply
            ip_datagram.source_address, ip_datagram.destination_address =\
                device.ip_address, ip_datagram.source_address
            ip_datagram.header_checksum = 0
            ip_datagram.header_checksum = calculate_checksum(
                ip_datagram.to_struct())
            frame.payload = ip_datagram.to_struct_with_payload()
            frame.destination, frame.source = frame.source, frame.destination
            return frame
        return
    print('Unknown IP datagram')
