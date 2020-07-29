from logger import Logger
from const import Const
from prt_cmd import BtCommandByte
from prt_packet import PRTPacket

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

    def __init__(self, logging, tag="SerialDataPacket"):
        self.logging = logging
        self.tag = tag
        self.state = None
        self.pkt_buf = bytearray()
        self.packet = None
        self.enter_state_init()


    def state_change_to(self, state):
        self.state = state
        self.logging.debug(
            "[{}]: enter state '{}'".format(self.tag, FSM.get_state_name(self.state)))

    def enter_state_init(self):
        self.state_change_to(FSM.INIT)
        self.pkt_len = 0
        self.crc32 = 0
    
    def enter_state_pkt_started(self):
        self.state_change_to(FSM.PKT_STARTED)
        # start a new packet
        del self.pkt_buf[:]

    def enter_state_got_len(self):
        self.state_change_to(FSM.GOT_LEN)
        self.pkt_len = int.from_bytes(self.pkt_buf[PKT_LEN_BYTE_INDEX:PKT_LEN_BYTE_INDEX+2], 'little')
        self.logging.debug(
            "[{}]: packet length = {}".format(self.tag, self.pkt_len))

    def enter_state_got_crc(self):
        self.state_change_to(FSM.GOT_CRC)
        crc32_start = PKT_BYTES_AFTER_LEN + self.pkt_len
        self.crc32 = int.from_bytes(
            self.pkt_buf[crc32_start:crc32_start+PKT_CRC_LEN], 'little')
        self.logging.debug(
            "[{}]: packet CRC32 = ({})".format(self.tag, hex(self.crc32)))

    def unpack_pkt_buf(self, pkt_buf):
        self.packet = PRTPacket()
        try:
            self.packet.unpack_data(pkt_buf, check_crc=False)
        except ValueError:
            self.logging.warn("ignored malformed packet.")

    def log_packet(self, packet):
        if packet.cmd == BtCommandByte.PRT_PRINT_DATA:
            self.logging.info(
                "[{}]: command '{} ({})', len={} ".format(self.tag,
                    BtCommandByte.findCommand(packet.cmd), hex(packet.cmd),
                    packet.len))
        else:
            self.logging.info(
                "[{}]: command '{} ({})', len={}, payload='{} (0x{}))'. ".format(
                    self.tag,
                    BtCommandByte.findCommand(packet.cmd), hex(packet.cmd),
                    packet.len, packet.payload, packet.payload.hex()))

    def parse_data(self, data, callback=None):
        self.logging.debug(
            "[{}]: parsing data ({})".format(self.tag, data.hex()))
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

                    self.unpack_pkt_buf(self.pkt_buf)
                    self.log_packet(self.packet)

                    if callback:
                        callback(self.pkt_buf)
            else:
                if self.state == FSM.INIT: # ignore packet outside bytes
                    self.logging.debug(
                        "[{}]: ignore outband data (0x{})".format(self.tag, byte.hex()))
                    continue

                self.pkt_buf.extend(byte)
                buf_len = len(self.pkt_buf)

                if self.state == FSM.PKT_STARTED and buf_len == PKT_BYTES_AFTER_LEN:
                    self.enter_state_got_len()
                elif self.state == FSM.GOT_LEN and buf_len == PKT_BYTES_AFTER_LEN + self.pkt_len + PKT_CRC_LEN:
                    self.enter_state_got_crc()


if __name__ == "__main__":
    count = 0
    log = Logger('serial_packet.log', level='debug')
    # Hex format data, 9 packets
    data = ['02', '0a00010001965bd24503023000010001965bd24503021f00010001965b',
            'd24503021000010001965bd24503022d00010001965bd24503024200010001965bd24503027f00010001965bd24503028100010001965bd24503020400010001965bd2',
            '4503']

    def get_packet(packet):
        global count
        log.logger.info(
            '#{} Test_Packet: {}'.format(count, packet.hex()))
        count += 1

    data_packet = SerialDataPacket(log.logger, 'TEST')
    for d in data:
        ds = bytes.fromhex(d)
        data_packet.parse_data(ds, get_packet)
