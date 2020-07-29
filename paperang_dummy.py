# Use bluetooth BLE 4.0 slave module to act as a dummy printer.
import struct
import serial
import serial.threaded

import time
from prt_cmd import BtCommandByte
from logger import Logger as Logger
from const import Const
from serial_packet import SerialDataPacket
from prt_packet import PRTPacket
from image_lib import ImageHandler

# pyserial tools
# python -m serial.tools.list_ports
# python -m serial.tools.miniterm <port_name>

COM_PORT= 'COM10'
BAUD = 115200
MAX_RECV_LEN = 1024


PRT_SN = b'P2B02004087288'
PRT_NAME = b'P2'
PRT_BAT_STATUS = 90
PRT_COUNTRY_NAME = b'CN'
PRT_CMD_42 = b'BK3432'
PRT_CMD_7F = '76332e33382e313900000000'  # Hex format
PRT_CMD_81 = '484d453233305f503200000000000000' # Hex format
PRT_VERSION = '080101'  # Hex format, 1.1.8
PRT_CMD_40 = b'\x00'
PRT_PWD_DOWN_TIME = 3600    # seconds
PRT_HEAT_DENSITY = 75       # %


class SerialHandler(serial.threaded.Protocol):
    """serial data handling"""

    def __init__(self, prt, logging):
        super(SerialHandler, self).__init__()
        self.prt = prt
        self.logging = logging
        self.count = 0
        self.data_packet = SerialDataPacket(logging, 'DUMMY')

    def __call__(self):
        return self

    def data_received(self, data):
        self.logging.debug('Host2Device_Data: {}'.format(data.hex()))
        super(SerialHandler, self).data_received(data)
        self.data_packet.parse_data(data, self.get_packet)

    def get_packet(self, packet):
        self.logging.info(
            '#{} Host2Device_Packet: {}'.format(self.count, packet.hex()))
        self.count += 1
        self.prt.handle_recv_pkt(packet)

class DummyPrinter:
    def __init__(self, log, port=COM_PORT, baud=BAUD):
        self.port = COM_PORT
        self.serial = serial.serial_for_url(COM_PORT, baudrate=baud, timeout=1,
                                          do_not_open= True)
        self.logging = log.logger
        self.serial_worker = None
        self.serial_handler = None
        self.intentional_exit = False
        self.count = 0
        self.crckey = Const.PKT_CRC_KEY

        # printer paramters
        self.power_down_time = PRT_PWD_DOWN_TIME
        self.heat_density = PRT_HEAT_DENSITY

        # other objects
        self.img_handler = ImageHandler()

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
        self.logging.info("#{} Device2Host_Packet: {}".format(self.count, data.hex()))
        self.count += 1

    def send_ack(self, cmd, ack=0):
        packet = PRTPacket(self.crckey)
        packet.cmd = cmd
        packet.payload = struct.pack('<B', ack)
        data = packet.pack_data()
        self.logging.debug(
            "sent ACK ({}) to command '{} ({})'. ".format(ack,
            BtCommandByte.findCommand(packet.cmd), hex(packet.cmd)))
        self.send_data(data)

    def send_msg(self, cmd, msg):
        packet = PRTPacket(self.crckey)
        packet.cmd = cmd
        packet.payload = msg
        data = packet.pack_data()
        self.logging.info(
            "sent MSG ({}) of command '{} ({})'. ".format(msg,
            BtCommandByte.findCommand(packet.cmd), hex(packet.cmd)))
        self.send_data(data)

    def set_crc32_key(self, key):
        self.crckey = key
        self.logging.info("CRC key set to {}".format(hex(key)))

    # ----------------  Command Handler ------------------------------
    def handle_other_cmds(self, packet):
        pass

    def handle_set_crc32_key(self, packet):
        self.set_crc32_key(int.from_bytes(packet.payload, 'little'))

    def handle_get_sn(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_SN, PRT_SN)

    def handle_get_dev_name(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_DEV_NAME, PRT_NAME)

    def handle_get_pwd_down_time(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_POWER_DOWN_TIME,
                      struct.pack('<H', self.power_down_time))

    def handle_get_bat_status(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_BAT_STATUS, struct.pack('<B', PRT_BAT_STATUS))

    def handle_get_country_name(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_COUNTRY_NAME,
                      PRT_COUNTRY_NAME)

    def handle_cmd_42(self, packet):
        self.send_msg(BtCommandByte.PRT_CMD_43,
                      PRT_CMD_42)

    def handle_cmd_7F(self, packet):
        self.send_msg(BtCommandByte.PRT_CMD_80,
                      bytes.fromhex(PRT_CMD_7F))

    def handle_cmd_81(self, packet):
        self.send_msg(BtCommandByte.PRT_CMD_82,
                      bytes.fromhex(PRT_CMD_81))

    def handle_get_version(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_VERSION, bytes.fromhex(PRT_VERSION))

    def handle_cmd_40(self, packet):
        self.send_msg(BtCommandByte.PRT_CMD_41,
                      bytes.fromhex(PRT_CMD_40))

    def handle_set_pwd_down_time(self, packet: PRTPacket):
        self.power_down_time = int.from_bytes(packet.payload, 'little')
        self.logging.info(
            "Power down time set to {}s".format(self.power_down_time))

    def handle_set_heat_density(self, packet: PRTPacket):
        self.heat_density = int.from_bytes(packet.payload, 'little')
        self.logging.info(
            "Heat density set to {}%".format(self.heat_density))

    def handle_get_heat_density(self, packet):
        self.send_msg(BtCommandByte.PRT_SENT_HEAT_DENSITY,
                      struct.pack('<B', self.heat_density))

    def handle_recv_cmd(self, packet: PRTPacket):
        cmd_handlers = {
            BtCommandByte.PRT_SET_CRC_KEY: self.handle_set_crc32_key,
            BtCommandByte.PRT_GET_SN: self.handle_get_sn,
            BtCommandByte.PRT_GET_DEV_NAME: self.handle_get_dev_name,
            BtCommandByte.PRT_GET_POWER_DOWN_TIME: self.handle_get_pwd_down_time,
            BtCommandByte.PRT_GET_BAT_STATUS: self.handle_get_bat_status,
            BtCommandByte.PRT_GET_COUNTRY_NAME: self.handle_get_country_name,
            BtCommandByte.PRT_CMD_42: self.handle_cmd_42,
            BtCommandByte.PRT_CMD_7F: self.handle_cmd_7F,
            BtCommandByte.PRT_CMD_81: self.handle_cmd_81,
            BtCommandByte.PRT_GET_VERSION: self.handle_get_version,
            BtCommandByte.PRT_CMD_40: self.handle_cmd_40,
            BtCommandByte.PRT_SET_POWER_DOWN_TIME: self.handle_set_pwd_down_time,
            BtCommandByte.PRT_SET_HEAT_DENSITY: self.handle_set_heat_density,
            BtCommandByte.PRT_GET_HEAT_DENSITY: self.handle_get_heat_density
        }
        if packet.cmd == BtCommandByte.PRT_PRINT_DATA:
            self.img_handler.process_image_data(packet)

        handler = cmd_handlers.get(packet.cmd, self.handle_other_cmds)
        if handler:
            handler(packet)
        self.send_ack(packet.cmd)

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
