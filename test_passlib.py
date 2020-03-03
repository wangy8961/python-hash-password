from passlib.context import CryptContext


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def test_passlib_demo():
    password = '123456'
    hashed_password = get_password_hash(password)
    assert verify_password('123456', hashed_password) is True
    assert verify_password('abc123', hashed_password) is False
