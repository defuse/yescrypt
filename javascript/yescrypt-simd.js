/*
 * This file must be loaded *after* yescrypt.js.
 * It replaces the implementations salsa20_8 and pwxform with SIMD versions.
 */





yescrypt.salsa20_8_simd = function (cell) {
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

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);


    OrigX0 = SIMD.Int32x4.add(OrigX0, X0);
    OrigX1 = SIMD.Int32x4.add(OrigX1, X1);
    OrigX2 = SIMD.Int32x4.add(OrigX2, X2);
    OrigX3 = SIMD.Int32x4.add(OrigX3, X3);

    SIMD.Int32x4.store(cell, 0,  OrigX0);
    SIMD.Int32x4.store(cell, 4,  OrigX1);
    SIMD.Int32x4.store(cell, 8,  OrigX2);
    SIMD.Int32x4.store(cell, 12, OrigX3);
}

yescrypt.salsa20_2_simd = function (cell) {
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

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.xor(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);


    OrigX0 = SIMD.Int32x4.add(OrigX0, X0);
    OrigX1 = SIMD.Int32x4.add(OrigX1, X1);
    OrigX2 = SIMD.Int32x4.add(OrigX2, X2);
    OrigX3 = SIMD.Int32x4.add(OrigX3, X3);

    SIMD.Int32x4.store(cell, 0,  OrigX0);
    SIMD.Int32x4.store(cell, 4,  OrigX1);
    SIMD.Int32x4.store(cell, 8,  OrigX2);
    SIMD.Int32x4.store(cell, 12, OrigX3);
}

yescrypt.pwxform_simd = function (pwxblock, sbox) {
    var zero = SIMD.Int32x4(0, 0, 0, 0);
    var ones = SIMD.Int32x4(1, 1, 1, 1);
    var low_ones = SIMD.Int32x4(1, 0, 1, 0);
    // Assumed by The ADD---Int64x2 macro. XXX: figure out how to say the macro's name correctly.
    var acc;

    var S0 = sbox.S0;
    var S1 = sbox.S1;
    var S2 = sbox.S2;

    for (var i = 0; i < this.PWXROUNDS; i++) {
        for (var j = 0; j < this.PWXGATHER; j++) {
            var x_lo = pwxblock[2 * j * this.PWXSIMPLE];
            var x_hi = pwxblock[2 * j * this.PWXSIMPLE + 1];

            var p0 = (x_lo & this.SMASK) / (this.PWXSIMPLE * 8);
            var p1 = (x_hi & this.SMASK) / (this.PWXSIMPLE * 8);

            var Bj = SIMD.Int32x4.load(pwxblock, 2 * j * this.PWXSIMPLE);
            var S1p1 = SIMD.Int32x4.load(sbox.S, S1 + 2 * p1 * this.PWXSIMPLE);

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
            AB_lo += sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + 0)];
            var carry = Math.floor(AB_lo / 4294967296);
            AB_lo = AB_lo % 4294967296;
            AB_hi += sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + 0) + 1] + carry;

            CD_lo += sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + 1)];
            var carry = Math.floor(CD_lo / 4294967296);
            CD_lo = CD_lo % 4294967296;
            CD_hi += sbox.S[S0 + 2 * (p0 * this.PWXSIMPLE + 1) + 1] + carry;

            Bj = SIMD.Int32x4(AB_lo, AB_hi, CD_lo, CD_hi);

            // XOR.
            Bj = SIMD.Int32x4.xor(Bj, S1p1);

            // Write back.
            SIMD.Int32x4.store(pwxblock, 2 * j * this.PWXSIMPLE, Bj);

            if (i != 0 && i != this.PWXROUNDS - 1) {
            // XXX: check this
                sbox.S[S2 + 2 * sbox.w] = SIMD.Int32x4.extractLane(Bj, 0);
                sbox.S[S2 + 2 * sbox.w + 1] = SIMD.Int32x4.extractLane(Bj, 1);
                sbox.w += 1;
                sbox.S[S2 + 2 * sbox.w] = SIMD.Int32x4.extractLane(Bj, 2);
                sbox.S[S2 + 2 * sbox.w + 1] = SIMD.Int32x4.extractLane(Bj, 3);
                sbox.w += 1;
            }
        }
    }

    sbox.S0 = S2;
    sbox.S1 = S0;
    sbox.S2 = S1;
    sbox.w = sbox.w & (this.SMASK / 8);
}

// XXX: Check if yescrypt.SWIDTH is tunable with our implementation? I think it is.
if (typeof SIMD !== 'undefined' && yescrypt.PWXSIMPLE == 2 && yescrypt.PWXGATHER == 4 && yescrypt.SWIDTH == 8) {
    yescrypt.salsa20_8 = yescrypt.salsa20_8_simd;
    yescrypt.salsa20_2 = yescrypt.salsa20_2_simd;
    // Make sure there's an error if something uses the unoptimized one.
    yescrypt.salsa20 = null;
    yescrypt.pwxform = yescrypt.pwxform_simd;
    yescrypt.using_simd = true;
}
