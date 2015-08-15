/*
 * This file must be loaded *after* yescrypt.js.
 * It replaces the implementations salsa20_8 and pwxform with SIMD versions.
 */

// TODO: we should check if SIMD is available and automatically replace if so.

define(`ARX',
    acc = SIMD.Int32x4.add($2, $3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, $4),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-$4)
    );
    $1 = SIMD.Int32x4.xor($1, acc);
)

define(`TWOROUNDS',
    ARX($2, $1, $4, 7)
    ARX($3, $2, $1, 9)
    ARX($4, $3, $2, 13)
    ARX($1, $4, $3, 18)

    $2 = SIMD.Int32x4.swizzle($2, 3, 0, 1, 2);
    $3 = SIMD.Int32x4.swizzle($3, 2, 3, 0, 1);
    $4 = SIMD.Int32x4.swizzle($4, 1, 2, 3, 0);

    ARX($4, $1, $2, 7)
    ARX($3, $4, $1, 9)
    ARX($2, $3, $4, 13)
    ARX($1, $2, $3, 18)

    $2 = SIMD.Int32x4.swizzle($2, 1, 2, 3, 0);
    $3 = SIMD.Int32x4.swizzle($3, 2, 3, 0, 1);
    $4 = SIMD.Int32x4.swizzle($4, 3, 0, 1, 2);
)

yescrypt.salsa20_8 = function (cell) {
    var X0 = SIMD.Int32x4.load(cell, 0);
    var X1 = SIMD.Int32x4.load(cell, 4);
    var X2 = SIMD.Int32x4.load(cell, 8);
    var X3 = SIMD.Int32x4.load(cell, 12);

    var OrigX0 = SIMD.Int32x4.load(cell, 0);
    var OrigX1 = SIMD.Int32x4.load(cell, 4);
    var OrigX2 = SIMD.Int32x4.load(cell, 8);
    var OrigX3 = SIMD.Int32x4.load(cell, 12);

    // Assumed by the arx macro. XXX: can't type A R X or it will expand!
    var acc;

    TWOROUNDS(X0, X1, X2, X3)
    TWOROUNDS(X0, X1, X2, X3)
    TWOROUNDS(X0, X1, X2, X3)
    TWOROUNDS(X0, X1, X2, X3)

    OrigX0 = SIMD.Int32x4.add(OrigX0, X0);
    OrigX1 = SIMD.Int32x4.add(OrigX1, X1);
    OrigX2 = SIMD.Int32x4.add(OrigX2, X2);
    OrigX3 = SIMD.Int32x4.add(OrigX3, X3);

    SIMD.Int32x4.store(cell, 0,  OrigX0);
    SIMD.Int32x4.store(cell, 4,  OrigX1);
    SIMD.Int32x4.store(cell, 8,  OrigX2);
    SIMD.Int32x4.store(cell, 12, OrigX3);
}

// TODO: Check the PWXFORM constants.

yescrypt.pwxform = function (pwxblock, sbox) {
    var zero = SIMD.Int32x4(0, 0, 0, 0);
    var ones = SIMD.Int32x4(1, 1, 1, 1);
    var low_ones = SIMD.Int32x4(1, 0, 1, 0);
    // Assumed by The ADD---Int64x2 macro. XXX: figure out how to say the macro's name correctly.
    var acc;

    for (var i = 0; i < this.PWXROUNDS; i++) {
        for (var j = 0; j < this.PWXGATHER; j++) {
            var x_lo = pwxblock[2 * j * this.PWXSIMPLE];
            var x_hi = pwxblock[2 * j * this.PWXSIMPLE + 1];

            var p0 = (x_lo & this.SMASK) / (this.PWXSIMPLE * 8);
            var p1 = (x_hi & this.SMASK) / (this.PWXSIMPLE * 8);

            var Bj = SIMD.Int32x4.load(pwxblock, 2 * j * this.PWXSIMPLE);
            var S1p1 = SIMD.Int32x4.load(sbox, this.SWORDS / 2 + 2 * p1 * this.PWXSIMPLE);

            // MULTIPLY.
            var hBj = SIMD.Int32x4.shiftRightLogicalByScalar(Bj, 16);
            var lBj = SIMD.Int32x4.and(Bj, SIMD.Int32x4.splat(0xFFFF));

            var AandB = SIMD.Int32x4.shuffle(lBj, hBj, 0, 4, 1, 5);
            var CandD = SIMD.Int32x4.shuffle(lBj, hBj, 2, 6, 3, 7);

            // Compute the products: AlBl, AhBh, BlAh, BhAl
            AandB = SIMD.Int32x4.mul(
                AandB,
                SIMD.Int32x4.swizzle(AandB, 2, 3, 1, 0)
            );
            // Compute the products: ClDl, ChDh, ClDh, ChDl
            CandD = SIMD.Int32x4.mul(
                CandD,
                SIMD.Int32x4.swizzle(CandD, 2, 3, 1, 0)
            );

            var AB_hi = (SIMD.Int32x4.extractLane(AandB, 1) >>> 0);
            acc = (
                        (SIMD.Int32x4.extractLane(AandB, 2) >>> 0) + (SIMD.Int32x4.extractLane(AandB, 3) >>> 0)
                      ) * 65536 +
                        (SIMD.Int32x4.extractLane(AandB, 0) >>> 0);
            var AB_lo = acc % 4294967296;
            AB_hi += Math.floor(acc / 4294967296);

            var CD_hi = (SIMD.Int32x4.extractLane(CandD, 1) >>> 0);
            acc = (
                        (SIMD.Int32x4.extractLane(CandD, 2) >>> 0) + (SIMD.Int32x4.extractLane(CandD, 3) >>> 0)
                      ) * 65536 +
                        (SIMD.Int32x4.extractLane(CandD, 0) >>> 0);
            var CD_lo = acc % 4294967296;
            CD_hi += Math.floor(acc / 4294967296);

            // ADD.
            AB_lo += sbox[2 * (p0 * this.PWXSIMPLE + 0)];
            var carry = Math.floor(AB_lo / 4294967296);
            AB_lo = AB_lo % 4294967296;
            AB_hi += sbox[2 * (p0 * this.PWXSIMPLE + 0) + 1] + carry;

            CD_lo += sbox[2 * (p0 * this.PWXSIMPLE + 1)];
            var carry = Math.floor(CD_lo / 4294967296);
            CD_lo = CD_lo % 4294967296;
            CD_hi += sbox[2 * (p0 * this.PWXSIMPLE + 1) + 1] + carry;

            Bj = SIMD.Int32x4(AB_lo, AB_hi, CD_lo, CD_hi);

            // XOR.
            Bj = SIMD.Int32x4.xor(Bj, S1p1);

            // Write back.
            SIMD.Int32x4.store(pwxblock, 2 * j * this.PWXSIMPLE, Bj);
        }
    }
}
