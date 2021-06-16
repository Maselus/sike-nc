from unittest import TestCase

from sike import generate_key, encapsulate, decapsulate


class SikeTest(TestCase):

    def test_api_flow(self):
        public_key, secret_key = generate_key()

        shared_secret_1, ciphertext_message = encapsulate(public_key)

        shared_secret_2 = decapsulate(secret_key, ciphertext_message)

        self.assertEqual(shared_secret_1, shared_secret_2)
        self.assertEqual(len(shared_secret_1), 32)
