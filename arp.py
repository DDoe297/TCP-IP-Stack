from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Tuple

from . import finals
from .ethernet import EthernetFrame
from .utils import get_mac_address_colon_format

if TYPE_CHECKING:
    from .device import NetDevice


class ArpTable(Dict[bytes, bytes]):
    def __str__(self) -> str:
        string_table: Dict[str, str] = dict()
        for ip_address, mac_address in self.items():
            string_table[socket.inet_ntoa(
                ip_address)] = get_mac_address_colon_format(mac_address)
        return json.dumps(string_table, sort_keys=True, indent=4)


@dataclass
class ArpHeader:
    hardware_type: int
    protocol_type: int
    operation: int
    data: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes] = struct.unpack('!2s2s1s1s2s', data[:8])
        self.hardware_type: int = int.from_bytes(header[0], 'big')
        self.protocol_type: int = int.from_bytes(header[1], 'big')
        self.hardware_size: bytes = header[2]
        self.protocol_size: bytes = header[3]
        self.operation: int = int.from_bytes(header[4], 'big')
        self.data: bytes = data[8:]

    def to_struct(self) -> bytes:
        hardware_type: bytes = self.hardware_type.to_bytes(2, 'big')
        protocol_type: bytes = self.protocol_type.to_bytes(2, 'big')
        operation: bytes = self.operation.to_bytes(2, 'big')
        return struct.pack('!2s2s1s1s2s',
                           hardware_type, protocol_type,
                           self.hardware_size, self.protocol_size,
                           operation)+self.data


@dataclass
class ArpIPv4Data:
    source_mac_address: bytes
    source_ip_address: bytes
    dstination_mac_address: bytes
    destination_ip_address: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes] = struct.unpack('!6s4s6s4s', data[:20])
        self.source_mac_address: bytes = header[0]
        self.source_ip_address: bytes = header[1]
        self.dstination_mac_address: bytes = header[2]
        self.destination_ip_address: bytes = header[3]

    def to_struct(self) -> bytes:
        return struct.pack('!6s4s6s4s',
                           self.source_mac_address, self.source_ip_address,
                           self.dstination_mac_address, self.destination_ip_address)


def reply_arp_request(frame: EthernetFrame, arp_header: ArpHeader,
                      arp_data: ArpIPv4Data, device: NetDevice) -> EthernetFrame:
    arp_data.destination_ip_address = arp_data.source_ip_address
    arp_data.dstination_mac_address = arp_data.source_mac_address
    arp_data.source_ip_address = device.ip_address
    arp_data.source_mac_address = device.mac_address
    arp_header.data = arp_data.to_struct()
    arp_header.operation = finals.ARP_REPLY
    frame.destination = frame.source
    frame.source = device.mac_address
    frame.protocol = 0x806
    frame.payload = arp_header.to_struct()
    return frame


def incoming_arp(frame: EthernetFrame, device: NetDevice) -> EthernetFrame | None:
    arp_header: ArpHeader = ArpHeader(frame.payload)
    if arp_header.hardware_type != finals.ARP_ETHERNET:
        print('Unsupported Hardware Type')
        return
    if arp_header.protocol_type != finals.ARP_IPV4:
        print('Unsupported Protocol Type')
        return
    arp_data: ArpIPv4Data = ArpIPv4Data(arp_header.data)
    device.update_arp_table(arp_data.source_ip_address,
                            arp_data.source_mac_address)
    if arp_data.destination_ip_address != device.ip_address:
        print(
            f'ARP Request for {socket.inet_ntoa(arp_data.destination_ip_address)}')
        return
    if arp_header.operation == finals.ARP_REQUEST:
        print('Replied ARP Request')
        return reply_arp_request(frame, arp_header, arp_data, device)
