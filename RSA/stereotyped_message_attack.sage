# stereotyped message attack
# sage -pip install pycryptodome

from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long

def stereotyped_message_attack(known, enc, pubkey, length):
    N, e = pubkey
    known = bytes_to_long(known.encode())
    P.<x> = PolynomialRing(Zmod(N))
    f = (known+x)^e - enc
    root = f.small_roots(X=(1<<length*8)-1)[0]
    return known+root

def generateKey():
    N, e = getPrime(1024)*getPrime(1024), 3
    return (N, e)

def encrypt(m, pubkey):
    m_ = bytes_to_long(m.encode())
    N, e = pubkey
    enc = pow(m_, e, N)
    return enc


def test():

    # Encrypt
    print('[+] Generating primes..')
    public_key = generateKey()
    password = 'v$aw4T:#'
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
