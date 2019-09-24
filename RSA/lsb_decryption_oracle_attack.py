from typing import *
from fractions import Fraction
from Crypto.Util.number import getPrime, inverse
import random


def lsb_decryption_oracle_attack(c, p, q, oracle):
    n = p*q
    e = 0x10001
    lower, upper = 0, Fraction(n)
    while upper-lower >= 1:
        C = c*pow(2, e, n)%n
        if oracle(C, p, q):
            lower = (lower+upper)/2
        else:
            upper = (lower+upper)/2

        print(upper-lower)
        if upper-lower < 1:
            return int(upper)
        c = C

def decrypt(c, p, q):
    e = 0x10001
    d = inverse(e, (p-1)*(q-1))
    n = p*q
    return pow(c, d, n)%2

def test():
    print('[+] Generating primes..')
    p, q = getPrime(512), getPrime(512)
    n = p*q
    phi = (p-1)*(q-1)
    e = 0x10001
    d = inverse(e, phi)
    m = 'LSB decryption oracle attack'
    m_ = int.from_bytes(m.encode(), 'big')
    print(f'[*] Message: {m}')

    enc = pow(m_, e, n)
    print(f'[*] Encrypted message: {enc}')

    print(f'[+] Start attacking')
    dec_ = lsb_decryption_oracle_attack(enc, p, q, decrypt)
    print(f'[+] Done')


    dec = dec_.to_bytes((dec_.bit_length()+7)//8, 'big').decode()
    print(f'[*] Decrypted message: {dec}')
    print(f'[*] (Message == Decrypted message) -> {m == dec}')

if __name__ == '__main__':
    test()
