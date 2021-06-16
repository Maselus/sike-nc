import logging

from Crypto.Cipher import AES


def remove_padding(s: str):
    return s.replace('~', '')


def padding(s):
    return s + ((16 - len(s) % 16) * '~')


class CommunicationMixin:

    def _send_message(self, socket):
        if self.is_secure:
            aes = AES.new(self.key.encode("utf8"), AES.MODE_CBC, IV=self.key.encode("utf8"))
        while True:
            raw_data = input()
            if raw_data:
                if self.is_secure:
                    encrypted_data = aes.encrypt(padding(raw_data).encode("utf8"))
                    logging.debug('Sending encrypted message: \n%s\n key: %s', encrypted_data,
                                  self.key)
                    socket.send(bytes(encrypted_data))
                else:
                    socket.send(bytes(raw_data, 'utf-8'))
