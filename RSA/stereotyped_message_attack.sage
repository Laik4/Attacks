# stereotyped message attack
# sage -pip install pycryptodome pycrypto

from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def stereotyped_message_attack(known, enc, pubkey, length):
    n, e = pubkey.n, pubkey.e
    known = bytes_to_long(known.encode())
    P.<x> = PolynomialRing(Zmod(n))
    f = (known+x)^e - enc
    root = f.small_roots()[0]
    return known+root


def encrypt(m, pubkey):
    n, e = pubkey.n, pubkey.e
    m = bytes_to_long(m.encode())
    return pow(m, e, n)


def test():

    # Encrypt
    print('[+] Generating primes..')
    public_key = RSA.generate(1024, e=3)
    password = 'v$a#'
    m = f'***Stereotyped message attack*** The password is {password}'
    enc = encrypt(m, public_key)

    print(f'[*] Message: {m}')
    print(f'[*] Encrypted message: {enc}')

    # Attack
    print(f'[+] Start attacking')
    known = f'***Stereotyped message attack*** The password is {chr(0)*len(password)}'
    dec_ = stereotyped_message_attack(known, enc, public_key, len(password))
    print(f'[+] Done')

    # Result
    dec = long_to_bytes(dec_).decode()
    print(f'[*] Decrypted message: {dec}')
    print(f'[*] (Message == Decrypted message) -> {m == dec}')

if __name__ == '__main__':
    test()
