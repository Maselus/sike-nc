import logging
import socket
import threading

from Crypto.Cipher import AES

from utils import CommunicationMixin, padding, remove_padding


class Server(CommunicationMixin):
    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM, secure=True):
        self.socket = socket.socket(socket_family, socket_type)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connection = None
        self.key = 'Sixteen byte key'
        self.is_secure = secure

    def key_exchange(self) -> int:
        pass

    def start(self, port):
        self.socket.bind(('localhost', port))
        logging.info('Listening on port %d...', port)
        self.socket.listen()
        try:
            self.connection, addr = self.socket.accept()
        except KeyboardInterrupt:
            self.socket.close()
            exit(0)

        with self.connection:
            logging.info('Connected by %s', addr[0])

            #key_exchange()

            aes = AES.new(self.key.encode("utf8"), AES.MODE_CBC, IV=self.key.encode("utf8"))

            input_thread = threading.Thread(target=self._send_message, args=[self.connection])
            input_thread.daemon = True
            input_thread.start()
            try:
                while True:
                    raw_data = self.connection.recv(1024)
                    if self.is_secure:
                        logging.debug('Received encrypted message: %s', raw_data)
                        decrypted_data = remove_padding(str(aes.decrypt(raw_data), 'utf-8'))
                        print('>', decrypted_data)
                    else:
                        print('>', str(raw_data, 'utf-8'))
                    if not raw_data:
                        break
            except KeyboardInterrupt:
                self.socket.close()
                exit(0)
        self.socket.close()

