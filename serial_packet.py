from logger import Logger
from const import Const
from prt_cmd import BtCommandByte


# state machine for serial data parser
class FSM:
    @staticmethod
    def get_state_name(state):
        keys = list(filter(lambda x: not x.startswith("__")
                           and FSM.__getattribute__(FSM, x) == state, dir(FSM)))
        return keys[0] if keys else "INVALID"

    INIT = 0
    PKT_STARTED = 1
    GOT_LEN = 2
    GOT_CRC = 3

#parse serial data to packet

PKT_CRC_LEN = 4   # bytes
# the byte index for packet length field
PKT_LEN_BYTE_INDEX = 3
# how long of bytes when received length info in packet
# 1 byte prefix + 1 byte cmd + 1 byte index + 2 bytes length
PKT_BYTES_AFTER_LEN = 5

class SerialDataPacket:
    pkt_buf = bytearray()

    def __init__(self, logging):
        self.logging = logging
        self.enter_state_init()

    def state_changed(self):
        self.logging.debug("enter state '{}'".format(FSM.get_state_name(self.state)))

    def enter_state_init(self):
        self.state = FSM.INIT
        self.pkt_len = 0
        self.crc32 = 0
        self.state_changed()
    
    def enter_state_pkt_started(self):
        self.state = FSM.PKT_STARTED
        # start a new packet
        del self.pkt_buf[:]
        self.state_changed()

    def enter_state_got_len(self):
        self.state = FSM.GOT_LEN
        self.pkt_len = int.from_bytes(self.pkt_buf[PKT_LEN_BYTE_INDEX:PKT_LEN_BYTE_INDEX+2], 'little')
        self.state_changed()

    def enter_state_got_crc(self):
        self.state = FSM.GOT_CRC
        crc32_start = PKT_BYTES_AFTER_LEN + self.pkt_len
        self.crc32 = int.from_bytes(
            self.pkt_buf[crc32_start:crc32_start+PKT_CRC_LEN], 'little')
        self.state_changed()

    def parse_data(self, data):
        for d in data:
            byte = d.to_bytes(1, 'little')
            if byte == Const.PKT_START_BYTE:
                if self.state == FSM.INIT:
                    self.enter_state_pkt_started()
                # should store byte after state check
                self.pkt_buf.extend(byte)
            elif byte == Const.PKT_STOP_BYTE:
                self.pkt_buf.extend(byte)
                if self.state == FSM.GOT_CRC:
                    self.enter_state_init()  # one packet received
                    return self.pkt_buf
            else:
                if self.state == FSM.INIT: # ignore packet outside bytes
                    self.logging.debug("ignore outband data (0x{})".format(byte.hex()))
                    continue

                self.pkt_buf.extend(byte)
                buf_len = len(self.pkt_buf)

                if self.state == FSM.PKT_STARTED and buf_len == PKT_BYTES_AFTER_LEN:
                    self.enter_state_got_len()
                elif self.state == FSM.GOT_LEN and buf_len == PKT_BYTES_AFTER_LEN + self.pkt_len + PKT_CRC_LEN:
                    self.enter_state_got_crc()
                    
        return None
