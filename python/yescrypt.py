class Yescrypt:

    def calculate(self, salt, N, r, p, t, g, flags, dkLen):
        pass

    def sMix(self, N, r, t, p, blocks, flags):
        pass

    def sMix1(self, r, block, N, outputblocks, flags, sbox):
        pass

    def sMix2(self, r, block, N, Nloop, outputblocks, flags, sbox):
        pass

    def blockmix_pwxform(self, r, block, sbox):
        pass

    def pwxform(self, pwxblock, sbox):
        pass

    def blockmix_salsa8(self, r, block):
        pass

    def salsa20_8(self, cell):
        pass

    def simd_shuffle_block(self, r, block):
        pass

    def simd_unshuffle_block(self, r, block):
        pass

    def integerify(self, r, block):
        pass

    def fNloop(self, n, t, flags):
        pass

    def p2floor(self, x):
        pass

    def wrap(self, x, i):
        pass

    def sha256(self, message):
        pass

    def hmac_sha256(self, key, message):
        pass

    def pbkdf2_sha256(self, password, salt, count, length):
        pass

