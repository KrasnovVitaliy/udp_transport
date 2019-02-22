#!/usr/bin/env python3

from Crypto.Cipher import AES
import hashlib
import logging
import os

logger = logging.getLogger(__name__)


class AESCipher(object):
    def gen_key(self, password):
        logger.info("Generate cipher key")
        # define 128-bit key from a text password
        key_128 = hashlib.md5(password.encode('utf8')).digest()
        logger.debug("Generated key: {}".format(key_128))
        return key_128

    def encrypt(self, key, data):
        logger.info("Encrypt data")
        logger.debug("Encrypt data {} with key: {}".format(data, key))

        iv = os.urandom(16)
        logger.debug("Generated IV: {}".format(iv))

        # text to crypt must be modulo 16 sized: add \x00 padding
        data += b'\x00' * (16 - len(data) % 16)
        logger.debug("Data with added text padding: {}".format(data))

        # do encrypt job
        encryptor = AES.new(key, AES.MODE_CBC, IV=iv)
        encrypted_data = encryptor.encrypt(data)
        logger.debug("Encrypted data: {}".format(encrypted_data))

        pub_msg = iv + encrypted_data
        logger.debug("Encrypted data with IV: {}".format(pub_msg))

        return pub_msg

    def decrypt(self, key, data):
        logger.info("Decrypt data")
        logger.debug("Decrypt data")

        # read from public message
        iv = data[:16]
        if len(iv) != 16:
            logger.error("IV did not find")
            return None

        logger.debug("Extracted IV: {}".format(iv))

        encrypted_data = data[16:]
        logger.debug("Encrypted data: {}".format(encrypted_data))

        # do decrypt job
        decryptor = AES.new(key, AES.MODE_CBC, IV=iv)
        decrypted_data = decryptor.decrypt(encrypted_data)
        logger.debug("Decrypted data: {}".format(decrypted_data))

        # remove text padding
        decrypted_data = decrypted_data.rstrip(b'\x00')
        logger.debug("Data with removed text padding: {}".format(decrypted_data))

        return decrypted_data


if __name__ == "__main__":
    # message to crypt with AES-128
    text = 'the secret message'

    aes_ecryption = AESCipher()
    key = aes_ecryption.gen_key(password="password123")
    encripted_data = aes_ecryption.encrypt(key=key, data=text.encode('utf8'));
    print("encripted_data: ", encripted_data)

    decrypted_data = aes_ecryption.decrypt(key=key, data=encripted_data)
    print(decrypted_data)
