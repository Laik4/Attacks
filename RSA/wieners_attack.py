from typing import *
from gmpy2 import is_square, iroot
from Crypto.Util.number import getPrime, inverse
import random


# reference: https://hackmd.io/@EopsDRtYQjOedimWuihKNg/ryhoUinFe?type=view
def rat_to_cfrac(a: int, b: int) -> Iterator[int]:
    while b > 0:
        x = a // b
        yield x
        a, b = b, a - x * b


def cfrac_to_rat_itr(cfrac: Iterable[int]) -> Iterator[Tuple[int, int]]:
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for q in cfrac:
        n = q*n1 + n0
        d = q*d1 + d0
        yield n, d
        n0, d0 = n1, d1
        n1, d1 = n, d


def conv_from_cfrac(cfrac: Iterable[int]) -> Iterator[Tuple[int, int]]:
    n_, d_ = 1, 0
    for i, (n, d) in enumerate(cfrac_to_rat_itr(cfrac)):
        yield n+(i+1)%2*n_, d+(i+1)%2*d_
        n_, d_ = n, d


def wieners_attack(e: int, n: int) -> Optional[int]:
    for k, dg in conv_from_cfrac(rat_to_cfrac(e, n)):
        edg = e * dg
        phi = edg // k

        x = n - phi + 1
        if x % 2 == 0 and is_square((x//2)**2 - n):
            g = edg - phi * k
            return dg // g
    return None



def test():
    print('[+] Generating primes..')
    p, q = -1, -1
    while not q < p < 2*q:
        p, q = getPrime(2048), getPrime(2048)
    n = p*q
    phi = (p-1)*(q-1)
    d = 0x10000000001
    e = inverse(d, phi)
    m = 'Wiener\'s attack'
    m_ = int.from_bytes(m.encode(), 'big')
    print(f'[*] Message: {m}')

    enc = pow(m_, e, n)
    print(f'[*] Encrypted message: {enc}')

    print(f'[+] Start attacking')
    d = wieners_attack(e, n)
    print(f'[+] Done')

    dec_ = pow(enc, d, n)
    dec = dec_.to_bytes((dec_.bit_length()+7)//8, 'big').decode()
    print(f'[*] Decrypted message: {dec}')
    print(f'[*] (Message == Decrypted message) -> {m == dec}')

if __name__ == '__main__':
    test()
