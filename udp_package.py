import struct
import constants
import logging
import mmh3
from aes_cipher import AESCipher

log_format = '%(asctime)-15s | %(levelname)s | %(filename)s | %(lineno)d: %(message)s'
logging.basicConfig(filemode='w', level=logging.DEBUG, format=log_format)
logger = logging.getLogger(__name__)


class UDPPackage(object):
    def __init__(self, pkg_type=constants.PKG_TYPE_HELLO, pkg_num=0, data=b'', password=None):
        self.pkg_type = pkg_type
        self.pkg_num = pkg_num
        self.data = data

        self.data_length = None
        self.data_hash = None
        self.data_length = self.__calculate_data_length__()
        self.data_hash = self.__calculate_data_hash__()

        self.password = password
        if self.password:
            self.cipher = AESCipher()

    def __calculate_data_length__(self):
        """
        Calculate package data length
        """
        return len(self.data)

    def __calculate_data_hash__(self):
        """
        Calculate package data hash
        """
        return mmh3.hash(self.data, signed=False)

    def __is_valid__(self):
        """
        Checking is received data valid
        :return:
        """
        logger.info("Checking is data valid")

        logger.debug("Data: {}".format(self.data))
        calculated_hash = self.__calculate_data_hash__()
        logger.debug("Calculated data hash: {}".format(calculated_hash))

        if calculated_hash != self.data_hash:
            logger.debug("Calculate hash {} does not equal to {}".format(calculated_hash, self.data_hash))
            return False

        return True

    def __encrypt__(self):
        """
        Encrypt package datae
        """

        logger.info("Encrypt package data")
        key = self.cipher.gen_key(password=self.password)
        self.data = self.cipher.encrypt(key=key, data=self.data)

    def __decrypt__(self):
        """
        Decrypt package data
        """
        key = self.cipher.gen_key(password=self.password)
        self.data = self.cipher.decrypt(key=key, data=self.data)

    def pack(self)-> bytearray:
        """
        Pack header and data to package
        :return: (byte array) Packed data to package
        """

        if self.password:
            self.__encrypt__()

        self.data_length = self.__calculate_data_length__()
        self.data_hash = self.__calculate_data_hash__()

        logger.info("Packing data to package")
        logger.debug("Data length: {}".format(self.data_length))
        logger.debug("Data hash: {}".format(self.data_hash))

        pkg_header = struct.pack("IIII", self.pkg_type, self.pkg_num, self.data_length, self.data_hash)
        logger.debug("Package header: {}".format(pkg_header))
        logger.debug("Package header length: {}".format(len(pkg_header)))

        logger.debug("Creating pkg bytearray")
        pkg = bytearray(pkg_header)
        pkg += self.data
        logger.debug("Data pkg: {}".format(pkg))
        logger.debug("Data pkg len: {}".format(len(pkg)))

        return pkg

    def unpack(self):
        """
        Unpack header and data from package
        :param data: Packed data package
        """

        self.pkg_type, self.pkg_num, self.data_length, self.data_hash = struct.unpack(
            'IIII', self.data[0:constants.TOTAL_HEADER_SIZE])
        self.data = self.data[constants.TOTAL_HEADER_SIZE:]

        self.data_length = self.__calculate_data_length__()
        self.data_hash = self.__calculate_data_hash__()
        logger.debug("Is data valid: {}".format(self.__is_valid__()))

        if self.password:
            self.__decrypt__()

    def send(self, sock: struct, addr: str, port: int):
        """
        Send data to socket
        :param sock: (struct) Socket
        :param addr: (string) Address
        :param port: (int) Port
        :return: Package object
        """
        sock.sendto(self.pack(), (addr, port))

    def receive(self, sock: struct, chunk_size: int = constants.CHUNK_SIZE) -> (struct, tuple):
        self.data, sender = sock.recvfrom(chunk_size + constants.TOTAL_HEADER_SIZE)
        logger.debug("Received: {}".format(self.data))
        logger.debug("From: {}".format(sender))

        self.unpack()
        return self, sender
