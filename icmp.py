import struct
from dataclasses import dataclass
from typing import Tuple

from . import finals
from .utils import calculate_checksum


@dataclass
class IcmpHeader:
    type: int
    code: int
    checksum: int
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[int] = struct.unpack('!BBH', data[:4])
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.payload = data[4:]

    def to_struct(self) -> bytes:
        return struct.pack('!BBH', self.type, self.code, self.checksum)+self.payload


def incoming_icmp(datagram_payload: bytes) -> bytes | None:
    if calculate_checksum(datagram_payload) != 0:
        return
    header: IcmpHeader = IcmpHeader(datagram_payload)
    if header.type == finals.ICMPV4_ECHO:
        header: IcmpHeader = reply_icmp_echo(header)
        return header.to_struct()

def reply_icmp_echo(header: IcmpHeader) -> IcmpHeader:
    header.type = finals.ICMPV4_REPLY
    header.checksum = 0
    header.checksum = calculate_checksum(header.to_struct())
    return header
