import binascii
import hashlib
import os


def get_password_hash(password):
    """Encrypt password with a salt using built-in `hashlib` library"""
    # 64 bits
    salt = hashlib.sha256(os.urandom(32)).hexdigest().encode('ascii')
    # generate HMAC from password, the key is salt
    hmac = hashlib.pbkdf2_hmac('sha256',  # The hash digest algorithm for HMAC
                               password.encode('utf-8'),  # Convert the password to bytes
                               salt,  # Provide the salt
                               100000)  # It is recommended to use at least 100,000 iterations of SHA-256
    # only ASCII chars(64 bits)
    hmac = binascii.hexlify(hmac)
    # hashed_password = salt + hmac
    return (salt + hmac).decode('ascii')


def verify_password(plain_password, hashed_password):
    """Check if further password is correct"""
    salt = hashed_password[:64]
    hmac = hashed_password[64:]
    new_hmac = hashlib.pbkdf2_hmac('sha256',
                                   plain_password.encode('utf-8'),
                                   salt.encode('ascii'),
                                   100000)
    new_hmac = binascii.hexlify(new_hmac).decode('ascii')
    return hmac == new_hmac


def test_hashlib_demo():
    password = '123456'
    hashed_password = get_password_hash(password)
    assert verify_password('123456', hashed_password) is True
    assert verify_password('abc123', hashed_password) is False
