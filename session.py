import sys
import socket
import logging
import constants
from udp_package import UDPPackage

log_format = '%(asctime)-15s | %(levelname)s | %(filename)s | %(lineno)d: %(message)s'
logging.basicConfig(filemode='w', level=logging.DEBUG, format=log_format)
logger = logging.getLogger(__name__)


class Session(object):
    def __init__(self, sock, addr=None, port=None, chunk_size=constants.CHUNK_SIZE, is_server=False, password=None):
        self.addr = addr
        self.port = port
        self.chunk_size = chunk_size
        self.sock = sock
        self.is_server = is_server
        self.password = password
        self.expected_chunks_count = 0

        self.__start__()

    def __start__(self):
        if self.is_server:
            self.__wait_session_start__()
            if self.is_active:
                self.__wait_data__()
        # else:
        #     self.__send_hello_message__()

    def __send_hello_message__(self, chunks_count=0):
        logger.debug("Sending hello message")
        encoded_chunks_count = ("{}".format(chunks_count)).encode('utf8')
        logger.debug("Encoded chunks count: {}".format(encoded_chunks_count))
        UDPPackage(pkg_type=constants.PKG_TYPE_HELLO, data=encoded_chunks_count).send(sock=self.sock, addr=self.addr,
                                                                                      port=self.port)
        self.sock.settimeout(5.0)
        received_package = UDPPackage()

        logger.debug("Wait ACK package")
        while True:
            received_package, sender = received_package.receive(sock=self.sock, chunk_size=constants.CHUNK_SIZE)
            logger.debug("Received package type: {}".format(received_package.pkg_type))
            if received_package.pkg_type == constants.PKG_TYPE_ACK:
                logger.debug("Received ACK package")
                break
        self.is_active = True

    def send_data(self, data):
        logger.debug("Sending data")

        sent_data_len = 0  # Already total sent data length
        data_len = len(data)  # Total data length
        total_chunks_count = int(data_len / self.chunk_size) + (data_len % self.chunk_size > 0)  # Data chunk size

        logger.debug("Total chunks count: {}".format(total_chunks_count))
        self.__send_hello_message__(chunks_count=total_chunks_count)

        sent_chunks = 0
        while sent_data_len < data_len:
            data_chunk = data[sent_data_len:sent_data_len + self.chunk_size]
            logger.debug("Send chunk num: {}/{} data: {}".format(sent_chunks, total_chunks_count, data_chunk))
            UDPPackage(pkg_type=constants.PKG_TYPE_DATA, pkg_num=sent_chunks, data=data_chunk,
                       password=self.password).send(
                sock=self.sock, addr=self.addr, port=self.port)
            sent_data_len += self.chunk_size
            sent_chunks += 1
        logger.debug("All data have been sent")
        # self.sock.settimeout(5.0)
        # received_package = UDPPackage()
        #
        # logger.debug("Wait ACK package")
        # while True:
        #     received_package, sender = received_package.receive(sock=self.sock, chunk_size=constants.CHUNK_SIZE)
        #     logger.debug("Received package type: {}".format(received_package.pkg_type))
        #     if received_package.pkg_type == constants.PKG_TYPE_ACK:
        #         logger.debug("Received ACK package")
        #         break
        # self.is_active = True

    def __wait_session_start__(self):
        logger.debug("Wait session start")
        received_package = UDPPackage()
        sender = None

        while True:
            logger.debug("Started wait session loop")
            received_package, sender = received_package.receive(sock=self.sock, chunk_size=constants.CHUNK_SIZE)
            logger.debug("Received package type: {} data: {}".format(
                received_package.pkg_type, received_package.data))

            if received_package.pkg_type == constants.PKG_TYPE_HELLO:
                logger.debug("Received hello package")
                logger.debug("Received data: {}".format(received_package.data))
                try:
                    self.expected_chunks_count = int(received_package.data)
                except Exception as e:
                    logger.warning("Could not convert chunks count to number: {}".format(e))

                logger.debug("Received expected chunks count: {}".format(self.expected_chunks_count))
                break

        logger.debug("Send ACK package")
        ack_package = UDPPackage(pkg_type=constants.PKG_TYPE_ACK)
        ack_package.send(sock=self.sock, addr=sender[0], port=sender[1])
        self.is_active = True

    def __wait_data__(self):
        logger.debug("Wait session data")
        received_data = {}
        while True:
            received_package = UDPPackage(password=self.password)
            if self.password:
                received_package, sender = received_package.receive(sock=self.sock,
                                                                    chunk_size=constants.CHUNK_SIZE + constants.IV_SIZE)
            else:
                received_package, sender = received_package.receive(sock=self.sock, chunk_size=constants.CHUNK_SIZE)
            logger.debug("Received package data: {} from {}".format(received_package.data, sender))

            if received_package.pkg_type == constants.PKG_TYPE_DATA:
                received_data[received_package.pkg_num] = received_package
                logger.debug("Send ACK package")
                ack_package = UDPPackage(pkg_type=constants.PKG_TYPE_ACK)
                ack_package.send(sock=self.sock, addr=sender[0], port=sender[1])

            if len(received_data) == self.expected_chunks_count:
                break

        output = ""
        for i in range(len(received_data)):
            print(received_data[i].data)
            output += received_data[i].data.decode('utf8')
        print(output)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = '127.0.0.1'
    port = 9000

    if sys.argv[1] == 'client':
        session = Session(sock=sock, addr=addr, port=port, password='test')
        session.send_data(data=b'Hello message from 12345')

    if sys.argv[1] == 'server':
        sock.bind((addr, port))
        session = Session(sock=sock, is_server=True, password='test')


if __name__ == "__main__":
    main()
