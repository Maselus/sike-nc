import argparse
import logging
import socket
import sys
import threading
import sike

from Crypto.Cipher import AES

BUFFER_SIZE = 1024
ENCODING = 'utf-16'

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'
NEW_LINE = '\n'

PRE_TEXT = NEW_LINE + CURSOR_UP_ONE + ERASE_LINE

EXCHANGE_CONFIRMATION = b'***CONFIRMED_EXCHANGE****'


def _print(raw_data):
    print(PRE_TEXT + '>' + raw_data)


def padding(s):
    return s + (((8 - len(s) % 8) - 1) * '~')


def remove_padding(s: str):
    return s.replace('~', '')


class SendMessageBase:
    def _send_message(self, socket):
        if self.is_secure:
            aes = AES.new(self.key, AES.MODE_CBC, IV=self.key[:16])
        while True:
            raw_data = input()
            if raw_data:
                if self.is_secure:
                    data = padding(raw_data).encode(ENCODING)
                    encrypted_data = aes.encrypt(data)
                    logging.debug('Sending encrypted message: \n%s\n key: %s', encrypted_data,
                                  self.key)
                    socket.send(bytes(encrypted_data))
                else:
                    socket.send(bytes(raw_data, ENCODING))


class Server(SendMessageBase):
    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM, secure=True):
        self.socket = socket.socket(socket_family, socket_type)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connection = None
        self.key = 'Sixteen byte key'
        self.is_secure = secure

    def key_exchange(self):
        logging.info('Exchanging key...')
        logging.debug('Waiting for public key response...')
        public_key = self.connection.recv(BUFFER_SIZE)
        logging.debug('Reviced public key: %s', public_key.hex())
        logging.info('Encapsulating key...')
        shared_secret, ciphertext = sike.encapsulate(public_key)
        logging.info('Sending cypher text message...')
        self.connection.sendall(ciphertext)
        logging.info('Waiting for confirmation...')
        confirmation = self.connection.recv(BUFFER_SIZE)
        if not confirmation == EXCHANGE_CONFIRMATION:
            self.socket.close()
        logging.info('Key exchanged.')

        logging.debug('Shared secret key is: %s', shared_secret.hex())
        return shared_secret

    def start(self, port):
        self.socket.bind(('', port))
        logging.info('Listening on port %d...', port)
        self.socket.listen()
        try:
            self.connection, addr = self.socket.accept()
        except KeyboardInterrupt:
            self.socket.close()
            print('Connection closed.')
            sys.exit(1)

        with self.connection:
            logging.info('Connected by %s', addr[0])
            aes = None
            if self.is_secure:
                self.key = self.key_exchange()
                aes = AES.new(self.key, AES.MODE_CBC, IV=self.key[:16])

            input_thread = threading.Thread(target=self._send_message, args=[self.connection])
            input_thread.daemon = True
            input_thread.start()
            try:
                while True:
                    raw_data = self.connection.recv(BUFFER_SIZE)
                    if self.is_secure:
                        logging.debug('Received encrypted message: %s', raw_data)
                        decrypted_data = remove_padding(str(aes.decrypt(raw_data), ENCODING))
                        _print(decrypted_data)
                    else:
                        _print(raw_data)
                    if not raw_data:
                        break
            except KeyboardInterrupt:
                pass
        self.socket.close()
        print('Connection closed.')


class Client(SendMessageBase):

    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM, secure=True):
        self.socket = socket.socket(socket_family, socket_type)
        self.key = 'Sixteen byte key'
        self.is_secure = secure

    def key_exchange(self):
        logging.info('Exchanging key...')
        logging.debug('Generating key pair...')
        public_key, secret_key = sike.generate_key()
        logging.debug('Generated public key: %s', public_key.hex())
        logging.debug('Generated secret key: %s', secret_key.hex())

        logging.debug('Sending public key...')
        self.socket.send(public_key)

        logging.debug('Waiting for cypher text response...')
        cyphertext_message = self.socket.recv(BUFFER_SIZE)
        logging.debug('Recived cypher text message: %s', cyphertext_message.hex())
        logging.info('Decapsulating shared key...')
        shared_secret = sike.decapsulate(secret_key, cyphertext_message)
        self.socket.send(EXCHANGE_CONFIRMATION)
        logging.info('Key exchanged.')
        logging.debug('Shared secret key is: %s', shared_secret.hex())
        return shared_secret

    def connect(self, destination, port):
        aes = None
        self.socket.connect((destination, port))
        logging.info('Connected with server')
        if self.is_secure:
            self.key = self.key_exchange()
            aes = AES.new(self.key, AES.MODE_CBC, IV=self.key[:16])

        input_thread = threading.Thread(target=self._send_message, args=[self.socket])
        input_thread.daemon = True
        input_thread.start()
        try:
            while True:
                raw_data = self.socket.recv(BUFFER_SIZE)
                if not raw_data:
                    break
                if self.is_secure:
                    logging.debug('Received encrypted message: %s', raw_data.hex())
                    decrypted_data = remove_padding(str(aes.decrypt(raw_data), ENCODING))
                    _print(decrypted_data)
                else:
                    _print(raw_data)
        except KeyboardInterrupt:
            pass

        self.socket.close()
        print('Connection closed.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen", help="Listen mode, for inbound connects",
                        action='store_true')
    parser.add_argument("-p", "--server-port", default=23456, type=int)
    parser.add_argument("-ns", "--not-secure", action='store_true')
    parser.add_argument("--log", type=str, default='INFO')
    parser.add_argument("destination", nargs='?')
    parser.add_argument("port", nargs='?', type=int)
    args = parser.parse_args()

    log_level = getattr(logging, args.log.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError('Invalid log level: %s' % args.log)
    logging.basicConfig(level=log_level, format='%(levelname)s:%(message)s')
    secure = not args.not_secure

    if args.listen and args.server_port:
        server = Server(secure=secure)
        try:
            server.start(port=args.server_port)
        except (Exception, KeyboardInterrupt) as e:
            server.socket.close()
            print('Connection closed.')
    elif args.destination and args.port:
        client = Client(secure=secure)
        try:
            client.connect(args.destination, args.port)
        except (Exception, KeyboardInterrupt) as e:
            client.socket.close()
            print('Connection closed.')
            raise
    else:
        raise Exception()


if __name__ == "__main__":
    main()
