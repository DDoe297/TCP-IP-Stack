import struct
from dataclasses import dataclass
from typing import Tuple


@dataclass
class EthernetFrame:
    destination: bytes
    source: bytes
    protocol: int
    payload: bytes

    def __init__(self, data: bytes) -> None:
        header: Tuple[bytes] = struct.unpack('!6s6s2s', data[:14])
        self.destination: bytes = header[0]
        self.source: bytes = header[1]
        self.protocol: int = int.from_bytes(header[2], 'big')
        self.payload: bytes = data[14:336]

    def to_struct(self) -> bytes:
        protocol: bytes = self.protocol.to_bytes(2, 'big')
        return struct.pack('!6s6s2s', self.destination, self.source, protocol)+self.payload
