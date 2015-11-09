// Requires the Stanford Javascript Cryptography Library (SJCL)
// https://bitwiseshiftleft.github.io/sjcl/

yescrypt = {};

yescrypt.PWXSIMPLE = 2;
yescrypt.PWXGATHER = 4;
yescrypt.PWXROUNDS = 6;
yescrypt.SWIDTH = 8;

yescrypt.PWXBYTES = yescrypt.PWXGATHER * yescrypt.PWXSIMPLE * 8;
yescrypt.PWXWORDS = yescrypt.PWXBYTES / 4;
yescrypt.SBYTES = 3 * (1 << yescrypt.SWIDTH) * yescrypt.PWXSIMPLE * 8;
yescrypt.SWORDS = yescrypt.SBYTES / 4;
yescrypt.SMASK = ((1 << yescrypt.SWIDTH) - 1) * yescrypt.PWXSIMPLE * 8;
yescrypt.RMIN = (yescrypt.PWXBYTES + 127) / 128;

yescrypt.YESCRYPT_RW = 1;
yescrypt.YESCRYPT_WORM = 2;
yescrypt.YESCRYPT_PREHASH = 0x100000;

yescrypt.using_simd = false;

yescrypt.calculate = function (password, salt, N, r, p, t, g, flags, dkLen) {

    if (!this.isInt32(flags) || (flags & ~(this.YESCRYPT_RW | this.YESCRYPT_WORM | this.YESCRYPT_PREHASH)) !== 0) {
        throw 'Unknown flags.';
    }

    if (!this.isInt32(N)) {
        throw 'N is not an integer.';
    }

    if (!this.isInt32(r)) {
        throw 'r is not an integer.';
    }

    if (!this.isInt32(p)) {
        throw 'p is not an integer.';
    }

    if (!this.isInt32(t)) {
        throw 't is not an integer.';
    }

    if (!this.isInt32(g)) {
        throw 'g is not an integer.';
    }

    if (!this.isInt32(dkLen)) {
        throw 'dkLen is not an itneger.';
    }

    if ((N & (N - 1)) !== 0) {
        throw 'N is not a power of two.';
    }

    if (N <= 1) {
        throw 'N is too small.';
    }

    if (r < 1) {
        throw 'r is too small.';
    }

    if (p < 1) {
        throw 'p is too small.';
    }

    if (g < 0) {
        throw 'g must be non-negative.';
    }

    if(flags === 0 && t !== 0) {
        throw 'Can not use t > 0 without flags.';
    }

    if (!this.isInt32(p * 128 * r)) {
        throw 'Integer overflow when calculating p * 128 * r.';
    }

    if ( (flags & this.YESCRYPT_RW) !== 0 && Math.floor(N/p) <= 1 ) {
        throw 'YESCRYPT_RW requires N/p >= 2.';
    }

    if ( (flags & this.YESCRYPT_RW) !== 0 && p >= 1 && Math.floor(N/p) >= 0x100 && Math.floor(N/p) * r >= 0x20000 ) {
        password = this.calculate(password, salt, N >> 6, r, p, 0, 0, flags | this.YESCRYPT_PREHASH, 32);
    }

    var dklen_g;
    for (var i = 0; i <= g; i++) {
        if (i == g) {
            dklen_g = dkLen;
        } else {
            dklen_g = 32;
        }

        password = this.yescrypt_kdf_body(password, salt, N, r, p, t, flags, dklen_g);

        // XXX: watch for overflow on this one
        N <<= 2;
        t >>>= 1;
    }

    return password;
};

/*
 * password:    a Uint8Array.
 * salt:        a Uint8Array.
 *
 * Returns:     a Uint8Array.
 */
yescrypt.yescrypt_kdf_body = function (password, salt, N, r, p, t, flags, dkLen) {

    if (flags != 0) {
        var key = "yescrypt";
        if ((flags & this.YESCRYPT_PREHASH) !== 0) {
            key += '-prehash';
        }
        password = this.hmac_sha256(
            this.convertStringToUint8Array(key),
            password
        );
    }

    var bytes = this.pbkdf2_sha256(password, salt, 1, p * 128 * r);
    // TODO: Switch endianness here on big-endian platforms.
    // View the PBKDF2 results as an array of Uint32.
    var B = new Uint32Array(bytes.buffer);

    if ( flags !== 0 ) {
        password = new Uint8Array(32);
        for (var i = 0; i < 32; i++) {
            password[i] = bytes[i];
        }
    }

    if ( (flags & this.YESCRYPT_RW) !== 0 ) {
        this.sMix(N, r, t, p, B, flags, password);
    } else {
        for (var i = 0; i < p; i++) {
            var Bi = new Uint32Array(B.buffer, B.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
            this.sMix(N, r, t, 1, Bi, flags);
        }
    }

    var result = this.pbkdf2_sha256(password, bytes, 1, Math.max(dkLen, 32));

    if ( (flags & (this.YESCRYPT_RW | this.YESCRYPT_WORM)) !== 0 && (flags & this.YESCRYPT_PREHASH) === 0) {
        var clientValue = new Uint8Array(result.buffer, result.byteOffset + 0, 32);
        var clientKey = this.hmac_sha256(
            clientValue,
            this.convertStringToUint8Array("Client Key")
        );
        var storedKey = this.sha256(clientKey);

        for (var i = 0; i < 32; i++) {
            result[i] = storedKey[i];
        }
    }

    // XXX we shouldn't be keeping around all that memory (gc attacks)
    return new Uint8Array(result.buffer, result.byteOffset + 0, dkLen);
};

yescrypt.sMix = function (N, r, t, p, blocks, flags, sha256) {
    // blocks should be p blocks (each 2*r cells).
    this.assert(blocks.length == p * 2 * r * 16);

    var sboxes = [];
    for (var i = 0; i < p; i++) {
        sbox = {
            S: new Uint32Array(this.SWORDS),
            S2: 0,
            S1: this.SWORDS / 3,
            S0: (this.SWORDS / 3) * 2,
            w: 0
        }
        sboxes.push(sbox);
    }

    var n = Math.floor(N / p);
    var Nloop_all = this.fNloop(n, t, flags);

    var Nloop_rw = 0;
    if ( (flags & this.YESCRYPT_RW) !== 0) {
        Nloop_rw = Math.floor(Nloop_all / p);
    }

    n = n - (n & 1);

    Nloop_all = Nloop_all + (Nloop_all & 1);
    Nloop_rw += 1;
    Nloop_rw = Nloop_rw - (Nloop_rw & 1);

    // Allocate N blocks.
    var V = new Uint32Array(N * 2 * r * 16);

    for (var i = 0; i < p; i++) {
        var v = i * n;
        if (i === p - 1) {
            n = N - v;
        }

        if ( (flags & this.YESCRYPT_RW) !== 0 ) {
            var twocells = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * 16);
            this.sMix1(1, twocells, this.SBYTES/128, sboxes[i].S, flags & ~this.YESCRYPT_RW, null);
            if (i == 0) {
                var for_sha256_update = new Uint8Array(
                    blocks.buffer,
                    blocks.byteOffset + (i * 2 * r * 16 + 2 * r * 16 - 16) * 4,
                    64
                );
                var sha256_updated = this.hmac_sha256(for_sha256_update, sha256);
                sha256.set(sha256_updated);
            }
        } else {
            sboxes[i] = null;
        }

        var BlockI = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
        var VPart = new Uint32Array(V.buffer, V.byteOffset + v * 2 * r * 16 * 4, n * 2 * r * 16);
        this.sMix1(r, BlockI, n, VPart, flags, sboxes[i]);

        this.sMix2(r, BlockI, this.p2floor(n), Nloop_rw, VPart, flags, sboxes[i]);
    }

    for (var i = 0; i < p; i++) {
        var BlockI = new Uint32Array(blocks.buffer, blocks.byteOffset + i * 2 * r * 16 * 4, 2 * r * 16);
        this.sMix2(r, BlockI, N, Nloop_all - Nloop_rw, V, flags & ~this.YESCRYPT_RW, sboxes[i]);
    }
};

yescrypt.sMix1 = function (r, block, N, outputblocks, flags, sbox) {

    this.simd_shuffle_block(r, block);

    for (var i = 0; i < N; i++) {
        // OutputBlock[i] = Block
        for (var j = 0; j < 2 * r * 16; j++) {
            outputblocks[i * 2 * r * 16 + j] = block[j];
        }

        if (false && i % 2 !== 0) {
            // TODO: ROM support.
        } else if ( (flags & this.YESCRYPT_RW) !== 0 && i > 1 ) {
            var j = this.wrap(this.integerify(r, block), i);
            // Block = Block XOR OutputBlocks[j]
            for (var k = 0; k < 2 * r * 16; k++) {
                block[k] ^= outputblocks[j * 2 * r * 16 + k];
            }
        }

        if (sbox === null) {
            this.blockmix_salsa8(r, block);
        } else {
            this.blockmix_pwxform(r, block, sbox);
        }
    }

    this.simd_unshuffle_block(r, block);
};

yescrypt.sMix2 = function (r, block, N, Nloop, outputblocks, flags, sbox) {

    this.simd_shuffle_block(r, block);

    for (var i = 0; i < Nloop; i++) {
        if (false && i % 2 !== 0) {
            // TODO: ROM support.
        } else {
            var j = this.integerify(r, block) & (N - 1);
            // Block = Block XOR OutputBlocks[j]
            for (var k = 0; k < 2 * r * 16; k++) {
                block[k] ^= outputblocks[j * 2 * r * 16 + k];
            }

            if ( (flags & this.YESCRYPT_RW) !== 0 ) {
                // OutputBlocks[j] = Block
                for (var k = 0; k < 2 * r * 16; k++) {
                    outputblocks[j * 2 * r * 16 + k] = block[k];
                }
            }
        }

        if (sbox === null) {
            this.blockmix_salsa8(r, block);
        } else {
            this.blockmix_pwxform(r, block, sbox);
        }
    }

    this.simd_unshuffle_block(r, block);
};

yescrypt.blockmix_pwxform = function (r, block, sbox) {
    this.assert(sbox !== null);

    var pwx_blocks = Math.floor(2 * r * 16 / this.PWXWORDS);

    var X = new Uint32Array(this.PWXWORDS);
    for (var i = 0; i < this.PWXWORDS; i++) {
        X[this.PWXWORDS - i - 1] = block[block.length - i - 1];
    }

    for (var i = 0; i < pwx_blocks; i++) {
        if (pwx_blocks > 1) {
            // X = X XOR PWXB[i]
            for (var j = 0; j < this.PWXWORDS; j++) {
                X[j] ^= block[i * this.PWXWORDS + j];
            }
        }

        this.pwxform(X, sbox);

        // PWXB[i] = X
        for (var j = 0; j < this.PWXWORDS; j++) {
            block[i * this.PWXWORDS + j] = X[j];
        }
    }

    // TODO: just make sure PWXWORDS is divisible by 16
    var i = Math.floor((pwx_blocks - 1) * this.PWXWORDS / 16);
    this.salsa20_2(new Uint32Array(block.buffer, block.byteOffset + i * 16 * 4, 16));

    // TODO: check this stuff
    for (i = i + 1; i < 2 * r; i++) {
        for (var j = 0; j < 16; j++) {
            block[i * 16 + j] ^= block[ (i - 1) * 16 + j ];
        }
        this.salsa20_2(new Uint32Array(block.buffer, block.byteOffset + i * 16 * 4, 16));
    }
};

yescrypt.pwxform = function (pwxblock, sbox) {
    this.assert(pwxblock.length === this.PWXWORDS);
    this.assert(sbox.S.length === this.SWORDS);

    var S0 = sbox.S0;
    var S1 = sbox.S1;
    var S2 = sbox.S2;

    for (var i = 0; i < this.PWXROUNDS; i++) {
        for (var j = 0; j < this.PWXGATHER; j++) {
            var x_lo = pwxblock[2 * j * this.PWXSIMPLE];
            var x_hi = pwxblock[2 * j * this.PWXSIMPLE + 1];

            var p0 = (x_lo & this.SMASK) / (this.PWXSIMPLE * 8);
            var p1 = (x_hi & this.SMASK) / (this.PWXSIMPLE * 8);

            for (var k = 0; k < this.PWXSIMPLE; k++) {
                var lo = pwxblock[2 * (j * this.PWXSIMPLE + k)];
                var hi = pwxblock[2 * (j * this.PWXSIMPLE + k) + 1];

                var s0_lo = sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + k)];
                var s0_hi = sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + k) + 1];

                var s1_lo = sbox.S[S1 + 2 * (p1 * this.PWXSIMPLE + k)];
                var s1_hi = sbox.S[S1 + 2 * (p1 * this.PWXSIMPLE + k) + 1];

                var mul_lo = 0;
                var mul_hi = 0;

                // See the PHP code for an explanation of this.

                var hA = (hi >> 16) & 0xFFFF;
                var lA = hi & 0xFFFF;
                var hB = (lo >> 16) & 0xFFFF;
                var lB = lo & 0xFFFF;

                mul_hi += hA * hB;

                var acc = ((hA * lB) * 65536) + ((hB * lA) * 65536) + (lA * lB);
                mul_lo += acc % 4294967296;
                mul_hi += Math.floor(acc / 4294967296);

                mul_lo += s0_lo;
                // XXX: better way?
                var carry = Math.floor(mul_lo / 4294967296);
                mul_lo = mul_lo % 4294967296;
                mul_hi += s0_hi + carry;

                mul_lo ^= s1_lo;
                mul_hi ^= s1_hi;

                // Make them positive after bitwise op.
                mul_lo >>>= 0;
                mul_hi >>>= 0;

                pwxblock[2 * (j * this.PWXSIMPLE + k)] = mul_lo;
                pwxblock[2 * (j * this.PWXSIMPLE + k) + 1] = mul_hi;

                if (i != 0 && i != this.PWXROUNDS - 1) {
                    sbox.S[S2 + 2 * sbox.w] = mul_lo;
                    sbox.S[S2 + 2 * sbox.w + 1] = mul_hi;
                    sbox.w += 1;
                }
            }
        }
    }

    sbox.S0 = S2;
    sbox.S1 = S0;
    sbox.S2 = S1;
    sbox.w = sbox.w & (this.SMASK / 8);
};

yescrypt.blockmix_salsa8 = function (r, block) {

    var X = new Uint32Array(16);
    for (var i = 0; i < 16; i++) {
        X[i] = block[ 16 * (2 * r - 1) + i ];
    }

    var Y = new Uint32Array(2 * r * 16);

    for (var i = 0; i < 2 * r; i++) {
        // X = X XOR Block[i]
        for (var j = 0; j < 16; j++) {
            X[j] ^= block[i * 16 + j];
        }
        this.salsa20_8(X);
        if (i % 2 === 0) {
            for (var j = 0; j < 16; j++) {
                Y[i/2 * 16 + j] = X[j];
            }
        } else {
            for (var j = 0; j < 16; j++) {
                Y[(r + (i-1)/2) * 16 + j] = X[j];
            }
        }
    }

    for (var i = 0; i < 2 * r * 16; i++) {
        block[i] = Y[i];
    }
};

yescrypt.salsa20_8 = function (cell) {
    this.salsa20(cell, 8);
}

yescrypt.salsa20_2 = function (cell) {
    this.salsa20(cell, 2);
}

yescrypt.salsa20 = function (cell, rounds) {
    // XXX: 0.5 hack... fix this when the spec is updated.
    this.simd_unshuffle_block(0.5, cell);

    var x = new Uint32Array(16);
    for (var i = 0; i < 16; i++) {
        x[i] = cell[i];
    }

    // This was partially copypasted from
    // https://raw.githubusercontent.com/neoatlantis/node-salsa20/master/salsa20.js
    function R(a, b){return (((a) << (b)) | ((a) >>> (32 - (b))));};
    for (var i = rounds; i > 0; i -= 2){
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
    };

    for (var i = 0; i < 16; i++) {
        cell[i] = (x[i] + cell[i]) & 0xffffffff;
    }

    this.simd_shuffle_block(0.5, cell);
};

yescrypt.simd_shuffle_block = function (r, block) {
    var saved = new Uint32Array(16);
    for (var i = 0; i < 2 * r; i++) {
        // Saved = Block[i]
        for (var j = 0; j < 16; j++) {
            saved[j] = block[i * 16 + (j * 5) % 16];
        }
        for (var j = 0; j < 16; j++) {
            block[i * 16 + j] = saved[j];
        }
    }
};

yescrypt.simd_unshuffle_block = function (r, block) {
    var saved = new Uint32Array(16);
    for (var i = 0; i < 2 * r; i++) {
        // Saved = Block[i]
        for (var j = 0; j < 16; j++) {
            saved[j] = block[i * 16 + j];
        }
        for (var j = 0; j < 16; j++) {
            block[i * 16 + (j * 5) % 16] = saved[j];
        }
    }
};

yescrypt.integerify = function (r, block) {
    return block[ (2 * r - 1) * 16 ]
};

yescrypt.fNloop = function (n, t, flags) {
    if ( (flags & this.YESCRYPT_RW) !== 0 ) {
        if (t === 0) {
            return Math.floor( (n + 2)/3 );
        } else if (t == 1) {
            return Math.floor( (2 * n + 2) / 3 );
        } else {
            return (t - 1) * n;
        }
    } else if ( (flags & this.YESCRYPT_WORM) !== 0 ) {
        if (t === 0) {
            return n;
        } else if (t == 1) {
            return n + Math.floor( (n + 1) / 2 );
        } else {
            return t * n;
        }
    } else {
        return n;
    }
};

yescrypt.p2floor = function (x) {
    var y;
    while ( (y = x & (x - 1)) !== 0 ) {
        x = y;
    }
    return x;
};

yescrypt.wrap = function (x, i) {
    var n = this.p2floor(i);
    return (x & (n - 1)) + (i - n);
};

yescrypt.sha256 = function (message) {
    message = this.convertUint8ArrayToBitArray(message);
    var result = sjcl.hash.sha256.hash(message);
    return this.convertBitArrayToUint8Array(result);
};

yescrypt.hmac_sha256 = function (key, message) {
    message = this.convertUint8ArrayToBitArray(message);
    key = this.convertUint8ArrayToBitArray(key);
    var hmac = new sjcl.misc.hmac(key);
    var result = hmac.mac(message);
    return this.convertBitArrayToUint8Array(result);
};

yescrypt.pbkdf2_sha256 = function (password, salt, count, length) {
    password = this.convertUint8ArrayToBitArray(password);
    salt = this.convertUint8ArrayToBitArray(salt);
    var result = sjcl.misc.pbkdf2(password, salt, count, length * 8);
    return this.convertBitArrayToUint8Array(result);
};

yescrypt.convertUint8ArrayToBitArray = function (uint8Array) {
    // Convert to hex...
    var hex = '';
    for (var i = 0; i < uint8Array.length; i++) {
        hex += (uint8Array[i] >> 4).toString(16);
        hex += (uint8Array[i] & 0x0F).toString(16);
    }
    // ...and then to bitArray.
    return sjcl.codec.hex.toBits(hex);
};

yescrypt.convertBitArrayToUint8Array = function (bitArray) {

    // Convert to hex...
    var hex = sjcl.codec.hex.fromBits(bitArray);
    // ...and then to Uint8Array.
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
        bytes[i/2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

yescrypt.convertStringToUint8Array = function (asciiString) {
    var bytes = new Uint8Array(asciiString.length);
    for (var i = 0; i < asciiString.length; i++) {
        bytes[i] = asciiString.charCodeAt(i);
    }
    return bytes;
}

// Copied from: http://stackoverflow.com/a/3885844
yescrypt.isInt32 = function (n) {
    return n === +n && n === (n | 0);
};

yescrypt.assert = function (truth_value, message) {
    message = message || 'No message given.'
    if (!truth_value) {
        throw 'Assertion failed. Message: ' + message;
    }
}
