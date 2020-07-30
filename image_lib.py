import cv2
import numpy as np
from prt_packet import PRTPacket
from prt_cmd import BtCommandByte

# Paperang width is fixed
WIDTH = 384

IMG_FILE_NAME = 'prt_img.bmp'
class ImageHandler:
    def __init__(self):
        self.img_data = bytearray()

    def process_image_data(self, packet: PRTPacket):
        if packet.cmd != BtCommandByte.PRT_PRINT_DATA:
            return

        self.img_data.extend(packet.payload)

    def gen_img(self):
        img_buf = bytearray()
        # extend each bit to one byte (bit 0 to 255, bit 1 to 0)
        for byte in self.img_data:
            for bit in range(7, -1, -1):
            #for bit in range(0, 8):
                if byte & 1<<bit:
                    img_buf.extend(b'\x00')
                else:
                    img_buf.extend(b'\xFF')
        del self.img_data

        img = np.frombuffer(img_buf, np.uint8)
        height = len(img) // WIDTH
        img = img.reshape([height, WIDTH, 1])
        return img

    def end_image_data(self):
        if len(self.img_data) == 0:
            return
        img = self.gen_img()
        cv2.imwrite(IMG_FILE_NAME, img)

