import time

from src.tokenvalidation import CryptoStore, TokenValidate, TokenEncrypt


store = CryptoStore()
store.generate_keys()

validate = TokenValidate(store)
encrypt = TokenEncrypt()

if 1:
    token = validate.generate_signed_token(time=1)
    print(validate.verify_signed_token(token))

    print(validate.verify_signed_token("not a token"))

    time.sleep(1)
    print(validate.verify_signed_token(token))

if 0:
    code = "123456"
    token = validate.generate_signed_token(time=1)
    etoken = encrypt.encrypt_token(token, code)

    code = "123456"
    dtoken = encrypt.decrypt_token(etoken, code)
    print(validate.verify_signed_token(dtoken))

    code = "654321"
    dtoken = encrypt.decrypt_token(etoken, code)
    print(validate.verify_signed_token(dtoken))

    time.sleep(1)
    code = "123456"
    dtoken = encrypt.decrypt_token(etoken, code)
    print(validate.verify_signed_token(dtoken))
