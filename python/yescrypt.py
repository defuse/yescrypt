
import hashlib
import hmac
# XXX: this import is over-broad
from array import *
from struct import *

# pip install pbkdf2 (or pip2 install pbkdf2)
from pbkdf2 import PBKDF2

PWXSIMPLE = 2;
PWXGATHER = 4;
PWXROUNDS = 6;
SWIDTH = 8;

PWXBYTES = PWXGATHER * PWXSIMPLE * 8;
PWXWORDS = PWXBYTES / 4;
SBYTES = 2 * (1 << SWIDTH) * PWXSIMPLE * 8;
SWORDS = SBYTES / 4;
SMASK = ((1 << SWIDTH) - 1) * PWXSIMPLE * 8;
RMIN = (PWXBYTES + 127) / 128;

YESCRYPT_RW = 1;
YESCRYPT_WORM = 2;
YESCRYPT_PREHASH = 0x100000;

def calculate(password, salt, N, r, p, t, g, flags, dkLen):

    if (flags & YESCRYPT_RW) != 0 and N//p <= 1:
        raise Exception("YESCRYPT_RW requires N/p >= 2")

    if (flags & YESCRYPT_RW) != 0 and p >= 1 and N//p >= 0x100 and N//p * r >= 0x20000:
        password = this.calculate(password, salt, N >> 6, r, p, 0, 0, flags | YESCRYPT_PREHASH, 32)

    if flags != 0:
        key = "yescrypt"
        if (flags & YESCRYPT_PREHASH) != 0:
            key += "-prehash"
        password = hmac_sha256(key, password)

    bbytes = pbkdf2_sha256(password, salt, 1, p * 128 * r)
    B = array('L', unpack('I' * (len(bbytes)//4), bbytes))

    if flags != 0:
        password = bytearray(32)
        for i in xrange(0, 32):
            password[i] = bbytes[i]

    if (flags & YESCRYPT_RW) != 0:
        sMix(N, r, t, p, B, flags)
    else:
        for i in xrange(0, p):
            Bi = B[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16]
            sMix(N, r, t, 1, Bi, flags)
            B[i * 2 * r * 16 : i * 2 * r * 16 + 2 * r * 16] = Bi

    bbytes = ''.join(pack('I', b) for b in B)
    result = pbkdf2_sha256(password, bbytes, 1, max(dkLen, 32))

    if (flags & (YESCRYPT_RW | YESCRYPT_WORM)) != 0 and (flags & YESCRYPT_PREHASH) == 0:
        clientValue = result[0:32]
        clientKey = hmac_sha256(clientValue, "Client Key")
        storedKey = sha256(clientKey)

        for i in xrange(0, 32):
            result[i] = storedKey[i]

    return result[0:dkLen]

def sMix(N, r, t, p, blocks, flags):

    sboxes = []
    for i in xrange(0, p):
        sboxes.append(array('L', [0] * SWORDS))

    n = N//p
    Nloop_all = fNloop(n, t, flags)

    Nloop_rw = 0
    if (flags & YESCRYPT_RW) != 0:
        Nloop_rw = Nloop_all // p

    n = n - (n & 1)

    Nloop_all = Nloop_all + (Nloop_all & 1)
    Nloop_rw = Nloop_rw - (Nloop_rw & 1)

    V = array('L', [0] * N * 2 * r * 16)

    for i in xrange(0, p):
        v = i * n
        if i == p - 1:
            n = N - v

        if (flags & YESCRYPT_RW) != 0:
            twocells = blocks[i * 2 * r * 16 : i * 2 * r * 16 + 32]
            sMix1(1, twocells, SBYTES//128, sboxes[i], flags & ~YESCRYPT_RW, None)
            blocks[i * 2 * r * 16: i * 2 * r * 16 + 32] = twocells
        else:
            sboxes[i] = None

        BlockI = blocks[i * 2 * r * 16 : i * 2 * r * 16 + 2 * r * 16]
        VPart = V[v * 2 * r * 16 : v * 2 * r * 16 + n * 2 * r * 16]
        sMix1(r, BlockI, n, VPart, flags, sboxes[i])
        sMix2(r, BlockI, p2floor(n), Nloop_rw, VPart, flags, sboxes[i])
        blocks[i * 2 * r * 16 : i * 2 * r * 16 + 2 * r * 16] = BlockI
        V[v * 2 * r * 16 : v * 2 * r * 16 + n * 2 * r * 16] = VPart

    for i in xrange(0, p):
        BlockI = blocks[i * 2 * r * 16 : i * 2 * r * 16 + 2 * r * 16]
        sMix2(r, BlockI, N, Nloop_all - Nloop_rw, V, flags & ~YESCRYPT_RW, sboxes[i])
        blocks[i * 2 * r * 16 : i * 2 * r * 16 + 2 * r * 16] = BlockI

def sMix1(r, block, N, outputblocks, flags, sbox):

    simd_shuffle_block(2*r, block)

    for i in xrange(0, N):
        for j in xrange(0, 2 * r * 16):
            outputblocks[i * 2 * r * 16 + j] = block[j]

        # XXX: ROM support left out
        if False:
            pass
        elif (flags & YESCRYPT_RW) != 0 and i > 1:
            j = wrap(integerify(r, block), i)
            for k in xrange(0, 2 * r * 16):
                block[k] ^= outputblocks[j * 2 * r * 16 + k]

        if sbox is None:
            blockmix_salsa8(r, block)
        else:
            blockmix_pwxform(r, block, sbox)

    simd_unshuffle_block(2*r, block)

def sMix2(r, block, N, Nloop, outputblocks, flags, sbox):

    simd_shuffle_block(2*r, block)

    for i in xrange(0, Nloop):
        # XXX: ROM support left out
        if False:
            pass
        else:
            j = integerify(r, block) & (N - 1)

            for k in xrange(0, 2 * r * 16):
                block[k] ^= outputblocks[j * 2 * r * 16 + k]

            if (flags & YESCRYPT_RW) != 0:
                for k in xrange(0, 2 * r * 16):
                    outputblocks[j * 2 * r * 16 + k] = block[k]

        if sbox is None:
            blockmix_salsa8(r, block)
        else:
            blockmix_pwxform(r, block, sbox)

    simd_unshuffle_block(2*r, block)

def blockmix_pwxform(r, block, sbox):

    pwx_blocks = (2 * r * 16) // PWXWORDS

    X = array('L', [0] * PWXWORDS)
    for i in xrange(0, PWXWORDS):
        X[PWXWORDS - i - 1] = block[len(block) - i - 1]

    for i in xrange(0, pwx_blocks):
        if pwx_blocks > 1:
            for j in xrange(0, PWXWORDS):
                X[j] ^= block[i * PWXWORDS + j]

        pwxform(X, sbox)

        for j in xrange(0, PWXWORDS):
            block[i * PWXWORDS + j] = X[j]


    # XXX: make a new array type with fast slicing
    i = (pwx_blocks - 1) * PWXWORDS // 16
    bi = block[i * 16 : (i * 16) + 16]
    salsa20_8(bi)
    for j in xrange(0, 16):
        block[i * 16 + j] = bi[j]

    i = i + 1
    while i < 2 * r:
        for j in xrange(0, 16):
            block[i * 16 + j] ^= block[ (i-1) * 16 + j ]

        bi = b[i * 16 : (i * 16) + 16]
        salsa20_8(bi)
        for j in xrange(0, 16):
            block[i * 16 + j] = bi[j]

        i += 1

def pwxform(pwxblock, sbox):

    for i in xrange(0, PWXROUNDS):
        for j in xrange(0, PWXGATHER):
            x_lo = pwxblock[2 * j * PWXSIMPLE]
            x_hi = pwxblock[2 * j * PWXSIMPLE + 1]

            p0 = (x_lo & SMASK) / (PWXSIMPLE * 8)
            p1 = (x_hi & SMASK) / (PWXSIMPLE * 8)

            for k in xrange(0, PWXSIMPLE):
                lo = pwxblock[2 * (j * PWXSIMPLE + k)]
                hi = pwxblock[2 * (j * PWXSIMPLE + k) + 1]

                s0_lo = sbox[2 * (p0 * PWXSIMPLE + k)]
                s0_hi = sbox[2 * (p0 * PWXSIMPLE + k) + 1]

                s1_lo = sbox[SWORDS / 2 + 2 * (p1 * PWXSIMPLE + k)]
                s1_hi = sbox[SWORDS / 2 + 2 * (p1 * PWXSIMPLE + k) + 1]

                # XXX: long/non-long side channel
                result = ((hi * lo) + s0_lo + (s0_hi << 32)) ^ s1_lo ^ (s1_hi << 32)
                result_lo = result & 0xffffffff
                result_hi = (result >> 32) & 0xffffffff

                pwxblock[2 * (j * PWXSIMPLE + k)] = result_lo
                pwxblock[2 * (j * PWXSIMPLE + k) + 1] = result_hi

def blockmix_salsa8(r, block):
    X = array('L', [0] * 16)

    for i in xrange(0, 16):
        X[i] = block[16 * (2 * r - 1) + i]

    Y = array('L', [0] * (2 * r * 16))

    for i in xrange(0, 2 * r):
        for j in xrange(0, 16):
            X[j] ^= block[i * 16 + j]
        salsa20_8(X)
        if i % 2 == 0:
            for j in xrange(0, 16):
                Y[i//2 * 16 + j] = X[j]
        else:
            for j in xrange(0, 16):
                Y[(r + (i-1)//2) * 16 + j] = X[j]

    for i in xrange(0, 2 * r * 16):
        block[i] = Y[i]

# Stolen from:  XXX: make any improvements to this
# https://github.com/ricmoo/pyscrypt/blob/master/pyscrypt/hash.py
def salsa20_8(B):
    '''Salsa 20/8 stream cypher; Used by BlockMix. See http://en.wikipedia.org/wiki/Salsa20'''

    simd_unshuffle_block(1, B)

    # Create a working copy
    x = B[:]

    # Expanded form of this code. The expansion is significantly faster but
    # this is much easier to understand
    # ROUNDS = (
    #     (4, 0, 12, 7),   (8, 4, 0, 9),    (12, 8, 4, 13),   (0, 12, 8, 18),
    #     (9, 5, 1, 7),    (13, 9, 5, 9),   (1, 13, 9, 13),   (5, 1, 13, 18),
    #     (14, 10, 6, 7),  (2, 14, 10, 9),  (6, 2, 14, 13),   (10, 6, 2, 18),
    #     (3, 15, 11, 7),  (7, 3, 15, 9),   (11, 7, 3, 13),   (15, 11, 7, 18),
    #     (1, 0, 3, 7),    (2, 1, 0, 9),    (3, 2, 1, 13),    (0, 3, 2, 18),
    #     (6, 5, 4, 7),    (7, 6, 5, 9),    (4, 7, 6, 13),    (5, 4, 7, 18),
    #     (11, 10, 9, 7),  (8, 11, 10, 9),  (9, 8, 11, 13),   (10, 9, 8, 18),
    #     (12, 15, 14, 7), (13, 12, 15, 9), (14, 13, 12, 13), (15, 14, 13, 18),
    # )
    #
    # for (destination, a1, a2, b) in ROUNDS:
    #     a = (x[a1] + x[a2]) & 0xffffffff
    #     x[destination] ^= ((a << b)  | (a >> (32 - b))) & 0xffffffff
    for i in (8, 6, 4, 2):
        a = (x[0] + x[12]) & 0xffffffff
        x[4] ^= ((a << 7) | (a >> 25))
        a = (x[4] + x[0]) & 0xffffffff
        x[8] ^= ((a << 9) | (a >> 23))
        a = (x[8] + x[4]) & 0xffffffff
        x[12] ^= ((a << 13) | (a >> 19))
        a = (x[12] + x[8]) & 0xffffffff
        x[0] ^= ((a << 18) | (a >> 14))
        a = (x[5] + x[1]) & 0xffffffff
        x[9] ^= ((a << 7) | (a >> 25))
        a = (x[9] + x[5]) & 0xffffffff
        x[13] ^= ((a << 9) | (a >> 23))
        a = (x[13] + x[9]) & 0xffffffff
        x[1] ^= ((a << 13) | (a >> 19))
        a = (x[1] + x[13]) & 0xffffffff
        x[5] ^= ((a << 18) | (a >> 14))
        a = (x[10] + x[6]) & 0xffffffff
        x[14] ^= ((a << 7) | (a >> 25))
        a = (x[14] + x[10]) & 0xffffffff
        x[2] ^= ((a << 9) | (a >> 23))
        a = (x[2] + x[14]) & 0xffffffff
        x[6] ^= ((a << 13) | (a >> 19))
        a = (x[6] + x[2]) & 0xffffffff
        x[10] ^= ((a << 18) | (a >> 14))
        a = (x[15] + x[11]) & 0xffffffff
        x[3] ^= ((a << 7) | (a >> 25))
        a = (x[3] + x[15]) & 0xffffffff
        x[7] ^= ((a << 9) | (a >> 23))
        a = (x[7] + x[3]) & 0xffffffff
        x[11] ^= ((a << 13) | (a >> 19))
        a = (x[11] + x[7]) & 0xffffffff
        x[15] ^= ((a << 18) | (a >> 14))
        a = (x[0] + x[3]) & 0xffffffff
        x[1] ^= ((a << 7) | (a >> 25))
        a = (x[1] + x[0]) & 0xffffffff
        x[2] ^= ((a << 9) | (a >> 23))
        a = (x[2] + x[1]) & 0xffffffff
        x[3] ^= ((a << 13) | (a >> 19))
        a = (x[3] + x[2]) & 0xffffffff
        x[0] ^= ((a << 18) | (a >> 14))
        a = (x[5] + x[4]) & 0xffffffff
        x[6] ^= ((a << 7) | (a >> 25))
        a = (x[6] + x[5]) & 0xffffffff
        x[7] ^= ((a << 9) | (a >> 23))
        a = (x[7] + x[6]) & 0xffffffff
        x[4] ^= ((a << 13) | (a >> 19))
        a = (x[4] + x[7]) & 0xffffffff
        x[5] ^= ((a << 18) | (a >> 14))
        a = (x[10] + x[9]) & 0xffffffff
        x[11] ^= ((a << 7) | (a >> 25))
        a = (x[11] + x[10]) & 0xffffffff
        x[8] ^= ((a << 9) | (a >> 23))
        a = (x[8] + x[11]) & 0xffffffff
        x[9] ^= ((a << 13) | (a >> 19))
        a = (x[9] + x[8]) & 0xffffffff
        x[10] ^= ((a << 18) | (a >> 14))
        a = (x[15] + x[14]) & 0xffffffff
        x[12] ^= ((a << 7) | (a >> 25))
        a = (x[12] + x[15]) & 0xffffffff
        x[13] ^= ((a << 9) | (a >> 23))
        a = (x[13] + x[12]) & 0xffffffff
        x[14] ^= ((a << 13) | (a >> 19))
        a = (x[14] + x[13]) & 0xffffffff
        x[15] ^= ((a << 18) | (a >> 14))


    # Add the original values
    for i in xrange(0, 16):
        B[i] = (B[i] + x[i]) & 0xffffffff

    simd_shuffle_block(1, B)

# ! NOTE ! The twiceR parameter here is different from the other
# implementations. The other implementations should be made to match this one.
def simd_shuffle_block(twiceR, block):
    # XXX: there's a better way to do this
    saved = array('L', [0] * 16)
    for i in xrange(0, twiceR):
        for j in xrange(0, 16):
            saved[j] = block[i * 16 + (j * 5) % 16]
        for j in xrange(0, 16):
            block[i * 16 + j] = saved[j]

def simd_unshuffle_block(twiceR, block):
    # XXX: there's a better way to do this
    saved = array('L', [0] * 16)
    for i in xrange(0, twiceR):
        for j in xrange(0, 16):
            saved[j] = block[i * 16 + j]
        for j in xrange(0, 16):
            block[i * 16 + (j * 5) % 16] = saved[j]

def integerify(r, block):
    return block[ (2 * r - 1) * 16 ]

def fNloop(n, t, flags):
    if (flags & YESCRYPT_RW) != 0:
        if t == 0:
            return (n + 2) // 3
        elif 1 == 1:
            return (2 * n + 2) // 3
        else:
            return (t - 1) * n
    elif (flags & YESCRYPT_WORM) != 0:
        if t == 0:
            return n
        elif t == 1:
            return n + (n+1)//2
        else:
            return t * n
    else:
        return n

def p2floor(x):
    y = x & (x - 1)
    while y != 0:
        x = y
        y = x & (x - 1)
    return x

def wrap(x, i):
    n = p2floor(i)
    return x & (n-1) + (i-n)

# XXX: return type of these?
def sha256(message):
    m = hashlib.sha256()
    m.update(str(message))
    return bytearray(m.digest())

def hmac_sha256(key, message):
    return bytearray(hmac.new(str(key), msg=str(message), digestmod=hashlib.sha256).digest())

# XXX hack
# https://stackoverflow.com/questions/3172536/issues-with-python-hashlib-sha256-2-4-3
class mysha256:
    digest_size = 32
    def new(self, inp=''):
        return hashlib.sha256(inp)

def pbkdf2_sha256(password, salt, count, length):
    # XXX the str() thing doesn't work in python3
    return bytearray(PBKDF2(str(password), str(salt), count, mysha256()).read(length))

