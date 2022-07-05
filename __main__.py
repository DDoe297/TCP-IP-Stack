from .data_handler import handler
from .device import NetDevice

if __name__ == '__main__':
    d: NetDevice = NetDevice(0x9cad972590e3, '192.168.1.103', 'wlp2s0')
    handler(d)
