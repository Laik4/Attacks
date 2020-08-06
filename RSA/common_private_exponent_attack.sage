# https://www.ijcsi.org/papers/IJCSI-9-2-1-311-314.pdf
def common_private_exponent_attack(e, N):
    r = len(e)
    assert len(e) == len(N) == r
    M = int(sqrt(N[r-1]))
    B = matrix([M, *e]).stack(matrix(ZZ, r, 1).augment(matrix(ZZ, r, r, lambda i, j: -N[i]*(i==j))))
    B = B.LLL()
    d = abs(B[0][0]) // M
    return d


e1, N1 = 587438623, 2915050561
e2, N2 = 2382816879, 3863354647
e3, N3 = 2401927159, 3943138939
e = [e1, e2, e3]
N = [N1, N2, N3]
d = common_private_exponent_attack(e, N)
print(d)




