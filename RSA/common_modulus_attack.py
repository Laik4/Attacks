from typing import *
from Crypto.Util.number import *

def ext_gcd(x: int, y: int) -> Tuple[int, int, int]:
    a, A = 1, 0
    b, B = 0, 1
    c, C = x, y
    while C:
        q, m = divmod(c, C)
        a, A = A, a - q*A
        b, B = B, b - q*B
        c, C = C, m
    return a, b, c

def common_modulus_attack(e1: int, e2: int, c1: int, c2: int, n: int) -> int:
    s1, s2, _ = ext_gcd(e1, e2)
    if s1 < 0:
        c1 = inverse(c1, n)
        s1 *= -1
    if s2 < 0:
        c2 = inverse(c2, n)
        s2 *= -1

    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


def test():
    print(f'[+] Generating primes')
    p, q = getPrime(2048), getPrime(2048)
    n = p*q
    phi = (p-1)*(q-1)
    e1, e2 = 0x10001, 0x10000
    d1, d2 = inverse(e1, phi), inverse(e2, phi)
    m = 'CommonModulusAttack'
    m_ = int.from_bytes(m.encode(), 'big')
    print(f'[*] Message: {m}')

    enc1 = pow(m_, e1, n)
    enc2 = pow(m_, e2, n)
    print(f'[*] Encrypted message1: {enc1}')
    print(f'[*] Encrypted message2: {enc2}')

    print(f'[+] Start attacking')
    dec_ = common_modulus_attack(e1, e2, enc1, enc2, n)
    print(f'[+] Done')

    dec = dec_.to_bytes((dec_.bit_length()+7)//8, 'big').decode()
    print(f'[*] Decrypted message: {dec}')
    print(f'[*] Message == Decrypted message -> {m == dec}')



if __name__ == '__main__':
    test()
