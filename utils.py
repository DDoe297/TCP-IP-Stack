def get_mac_address_colon_format(mac: bytes) -> str:
    return f'{mac[0]:02x}:{mac[1]:02x}:{mac[2]:02x}:{mac[3]:02x}:{mac[4]:02x}:{mac[5]:02x}'


def calculate_checksum(data: bytes) -> int:
    data_pointer: int = 0
    data_length: int = len(data)
    checksum: int = 0
    while data_length > 0:
        checksum += int.from_bytes(data[data_pointer:data_pointer+2], 'big')
        data_pointer += 2
        data_length -= 2
    while checksum >> 16:
        checksum: int = (checksum & 0xFFFF) + (checksum >> 16)
    return (~checksum) & 0xFFFF
