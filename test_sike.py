import time
from unittest import TestCase

from sike import CtypeSikeApi

sike_api = CtypeSikeApi()


def generate_key():
    sike_api.generate_key()


class SikeTest(TestCase):
    def setUp(self) -> None:
        self.sike_api = CtypeSikeApi()

    def test_api_flow(self):
        public_key, secret_key = self.sike_api.generate_key()

        shared_secret_1, ciphertext_message = self.sike_api.encapsulate(public_key)

        shared_secret_2 = self.sike_api.decapsulate(secret_key, ciphertext_message)

        self.assertEqual(shared_secret_1, shared_secret_2)
        self.assertEqual(len(shared_secret_1), 32)

    def test_time(self):
        start_time = time.time()
        public_key, secret_key = self.sike_api.generate_key()
        t = time.time() - start_time
        print('%s: %.3f s' % ('generate key: ', t))

        start_time = time.time()
        shared_secret_1, ciphertext_message = self.sike_api.encapsulate(public_key)
        t = time.time() - start_time
        print('%s: %.3f s' % ('encapsulate: ', t))

        start_time = time.time()
        shared_secret_2 = self.sike_api.decapsulate(secret_key, ciphertext_message)
        t = time.time() - start_time
        print('%s: %.3f s' % ('decapsulate: ', t))

        self.assertEqual(shared_secret_1, shared_secret_2)
        self.assertEqual(len(shared_secret_1), 32)
