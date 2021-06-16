import logging
import socket
import sys
import threading

from Crypto.Cipher import AES

from utils import CommunicationMixin, padding, remove_padding


class Client(CommunicationMixin):

    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM, secure=True):
        self.socket = socket.socket(socket_family, socket_type)
        self.key = 'Sixteen byte key'
        self.is_secure = secure

    def connect(self, destination, port):
        self.socket.connect((destination, port))
        logging.info('Connected with server')

        # key_exchange()

        aes = AES.new(self.key.encode("utf8"), AES.MODE_CBC, IV=self.key.encode("utf8"))

        input_thread = threading.Thread(target=self._send_message, args=[self.socket])
        input_thread.daemon = True
        input_thread.start()
        try:
            while True:
                raw_data = self.socket.recv(1024)
                if not raw_data:
                    break
                if self.is_secure:
                    logging.debug('Received encrypted message: %s', raw_data)
                    decrypted_data = remove_padding(str(aes.decrypt(raw_data), 'utf-8'))
                    print('>', decrypted_data)
                else:
                    print('>', str(raw_data, 'utf-8'))
        except KeyboardInterrupt:
            self.socket.close()
            exit(0)
        self.socket.close()
