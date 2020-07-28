import struct
import zlib
from const import Const
from prt_cmd import BtCommandByte


class PRTPacket:
    def __init__(self, crckeyset=Const.PKT_CRC_KEY):
        self.crckey = crckeyset
        self.prefix = Const.PKT_START  # 1 byte
        self.cmd = 0             # 1 byte: command
        self.index = 0           # 1 byte: packet index for same command
        self.len = 0             # 2 bytes: payload length
        self.payload = bytes()   # n bytes: payload
        self.crc32 = 0           # 4 bytes: CRC32 of payload
        self.suffix = Const.PKT_STOP   # 1 byte

        self.crckey = Const.PKT_CRC_KEY

    def calc_crc32(self, content):
        return zlib.crc32(content, self.crckey)

    # not implemented. raise ValueError if checksum failed
    def check_crc32(self):
        pass

    # pack to bytes data
    def pack_data(self):
        data = struct.pack('<BBB', self.prefix, self.cmd, self.index)
        self.len = len(self.payload)
        data += struct.pack('<H', self.len)
        data += self.payload
        self.crc32 = self.calc_crc32(self.payload)
        data += struct.pack('<I', self.crc32)
        data += struct.pack('<B', self.suffix)

        return data

    def unpack_data(self, byte_data, check_crc=True):
        try:
            self.prefix, self.cmd, self.index, self.len = struct.unpack(
                '<BBBH', byte_data[0:5])
            self.payload = byte_data[5: 5 + self.len]
            base = 5 + self.len
            self.crc32 = struct.unpack('<I', byte_data[base: base+4])[0]
            self.suffix = struct.unpack('<B', byte_data[base+4: base+5])[0]

            if self.prefix != Const.PKT_START or self.suffix != Const.PKT_STOP:
                raise ValueError("wrong packet format")

            # Do not check CRC for PRT_SET_CRC_KEY command
            if check_crc and self.cmd != BtCommandByte.PRT_SET_CRC_KEY:
                self.check_crc32()
        except:
            raise ValueError("wrong packet format")

    # peek command in a packet data without unpack it all
    def peek_cmd(self, byte_data):
        _, cmd = struct.unpack(
            '<BB', byte_data[0:2])

        return cmd
