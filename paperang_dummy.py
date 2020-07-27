# Use bluetooth BLE 4.0 slave module to act as a dummy printer.

import serial
import serial.threaded
import struct
import zlib
import time
from const import BtCommandByte
from logger import Logger as Logger

# pyserial tools
# python -m serial.tools.list_ports
# python -m serial.tools.miniterm <port_name>

COM_PORT= 'COM10'
BAUD = 9600
MAX_RECV_LEN = 1024
PKT_START_BYTE = b'\x02'
PKT_START = 2
PKT_STOP_BYTE = b'\x03'
PKT_STOP = 3

PKT_CRC_KEY = 0x35769521

PRT_SN = b'P2B0200810E4B4'
PRT_NAME = b'P2'
PRT_PWD_DOWN_TIME = 3600   # seconds

class PRTPacket:
    prefix = PKT_START  # 1 byte
    cmd = 0             # 1 byte: command
    index = 0           # 1 byte: packet index for same command
    len = 0             # 2 bytes: payload length
    payload = bytes()   # n bytes: payload
    crc32 = 0           # 4 bytes: CRC32 of payload
    suffix = PKT_STOP   # 1 byte

    crckey = PKT_CRC_KEY

    def __init__(self, crckeyset=PKT_CRC_KEY):
        super().__init__()
        self.crckey = crckeyset

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
            self.payload = byte_data[5 : 5 + self.len]
            base = 5 + self.len
            self.crc32 = struct.unpack('<I', byte_data[base: base+4])[0]
            self.suffix = struct.unpack('<B', byte_data[base+4: base+5])[0]

            if self.prefix != PKT_START or self.suffix != PKT_STOP:
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

class SerialHandler(serial.threaded.Protocol):
    """serial data handling"""
    in_packet = False
    packet_buf = bytearray()

    def __init__(self, prt, logging):
        super(SerialHandler, self).__init__()
        self.prt = prt
        self.logging = logging

    def __call__(self):
        return self

    def data_received(self, data):
        self.logging.debug('Host2Device Data: {}'.format(data.hex()))
        super(SerialHandler, self).data_received(data)
        self.get_packet(data)

    def get_packet(self, data):
        """Find data enclosed in START/STOP"""
        for d in data:
            byte = d.to_bytes(1, 'little')
            if byte == PKT_START_BYTE:
                self.in_packet = True
                self.packet_buf.extend(byte)
            elif byte == PKT_STOP_BYTE:
                self.in_packet = False
                self.packet_buf.extend(byte)
                self.logging.info(
                    'Host2Device Packet: {}'.format(self.packet_buf.hex()))
                self.prt.handle_recv_pkt(self.packet_buf)
                del self.packet_buf[:]
            elif self.in_packet:
                self.packet_buf.extend(byte)
            else:  # data that is received outside of packets
                pass

class DummyPrinter:
    serial_worker = None
    serial_handler = None
    intentional_exit = False
    new_crckey = False
    crckey = PKT_CRC_KEY

    def __init__(self, log, port=COM_PORT, baud=BAUD):
        self.port = COM_PORT
        self.serial = serial.serial_for_url(COM_PORT, baudrate=baud, timeout=1,
                                          do_not_open= True)
        self.logging = log.logger

    def connect_host(self):
        try:
            self.serial.open()
        except serial.SerialException as e:
            self.logging.error(
                'Could not open serial port {}: {}\n'.format(self.port, e))
            return False
        self.logging.info("Host connected({}).".format(self.port))
        return True

    def disconnect_host(self):
        self.serial.close()
        self.logging.info("Host disconnected({}).".format(self.port))

    def start_serial_worker(self):
        # start thread to handle serial data
        self.serial_handler = SerialHandler(self, self.logging)
        self.serial_worker = serial.threaded.ReaderThread(
            self.serial, self.serial_handler)
        self.serial_worker.start()
        self.logging.info("Start to handle serial data ...")
        try:
            while not self.intentional_exit:
                time.sleep(1)
        except KeyboardInterrupt:
            self.intentional_exit = True
            raise

    def send_data(self, data):
        self.serial.write(data)
        self.logging.info("Device2Host Packet: {}".format(data.hex()))

    def send_ack(self, cmd, ack=0):
        packet = PRTPacket(self.crckey)
        packet.cmd = BtCommandByte.PRT_SET_CRC_KEY
        packet.payload = struct.pack('<B', ack)
        data = packet.pack_data()
        self.send_data(data)
        self.logging.info("sent ACK ({}) to command '{}'. ".format(ack,
            packet.cmd))
    
    def send_msg(self, cmd, msg):
        packet = PRTPacket(self.crckey)
        packet.cmd = cmd
        packet.payload = msg
        data = packet.pack_data()
        self.send_data(data)
        self.logging.info("sent MSG ({}) to command '{}'. ".format(msg,
            packet.cmd))       

    def set_crc32_key(self, key):
        self.new_crckey = True
        self.crckey = key
        self.logging.info("CRC key set to {}".format(hex(key)))

    # ----------------  Command Handler ------------------------------
    def handle_set_crc32_key(self, packet):
        self.set_crc32_key(int.from_bytes(packet.payload, 'little'))
        self.send_ack(BtCommandByte.PRT_SET_CRC_KEY)

    def handle_get_sn(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_SN, PRT_SN)
        self.send_ack(BtCommandByte.PRT_SENT_SN)

    def handle_get_dev_name(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_SN, PRT_NAME)
        self.send_ack(BtCommandByte.PRT_GET_DEV_NAME)

    def handle_get_pwd_down_time(self, packet):
        self.send_ack(BtCommandByte.PRT_GET_POWER_DOWN_TIME)

    def handle_other_cmds(self, packet):
        pass

    def handle_recv_cmd(self, packet: PRTPacket):
        cmd_handlers = {
            BtCommandByte.PRT_SET_CRC_KEY: self.handle_set_crc32_key,
            BtCommandByte.PRT_GET_SN: self.handle_get_sn,
            BtCommandByte.PRT_GET_DEV_NAME: self.handle_get_dev_name,
            BtCommandByte.PRT_GET_POWER_DOWN_TIME: self.handle_get_pwd_down_time
        }
        handler = cmd_handlers.get(packet.cmd, self.handle_other_cmds)
        if handler:
            handler(packet)

    def handle_recv_pkt(self, rec_pkt):
        packet = PRTPacket(self.crckey)
        try:
            packet.unpack_data(rec_pkt)
            self.handle_recv_cmd(packet)
        except ValueError:
            self.logging.warn("ignored malformed packet.")

    def enable(self):
        if not self.connect_host():
            return False
        self.intentional_exit = False
        self.start_serial_worker()

    def disable(self):
        self.disconnect_host()
        self.serial_worker.stop()
        self.intentional_exit = True


if __name__ == "__main__":
    log = Logger('Paperang_dummy.log', level='info')

    prt = DummyPrinter(log)
    prt.enable()
