/*
 * This file must be loaded *after* yescrypt.js.
 * It replaces the implementations salsa20_8 and pwxform with SIMD versions.
 */

// TODO: we should check if SIMD is available and automatically replace if so.







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

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);

    acc = SIMD.Int32x4.add(X0, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X2);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 18),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-18)
    );
    X0 = SIMD.Int32x4.xor(X0, acc);


    X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
    X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
    X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

    acc = SIMD.Int32x4.add(X0, X1);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 7),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-7)
    );
    X3 = SIMD.Int32x4.xor(X3, acc);

    acc = SIMD.Int32x4.add(X3, X0);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 9),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-9)
    );
    X2 = SIMD.Int32x4.xor(X2, acc);

    acc = SIMD.Int32x4.add(X2, X3);
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, 13),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-13)
    );
    X1 = SIMD.Int32x4.xor(X1, acc);

    acc = SIMD.Int32x4.add(X1, X2);
    acc = SIMD.Int32x4.or(
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

// TODO: Check the PWXFORM constants.

yescrypt.pwxform = function (pwxblock, sbox) {
    this.assert(this.PWXSIMPLE == 2)

    var zero = SIMD.Int32x4(0, 0, 0, 0);
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
            var S0p0 = SIMD.Int32x4.load(sbox, 2 * p0 * this.PWXSIMPLE);
            var S1p1 = SIMD.Int32x4.load(sbox, this.SWORDS / 2 + 2 * p1 * this.PWXSIMPLE);

            // MULTIPLY.
            var parts = SIMD.Int16x8.fromInt32x4Bits(Bj);
            var A = SIMD.Int16x8.swizzle(parts, 0, 0, 1, 0, 2, 0, 3, 0);
            A = SIMD.Int16x8.and(
                    A,
                    SIMD.Int16x8(0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0)
            );
            A = SIMD.Int32x4.fromInt16x8Bits(A);
            var B = SIMD.Int16x8.swizzle(parts, 4, 0, 5, 0, 6, 0, 7, 0);
            B = SIMD.Int16x8.and(
                    B,
                    SIMD.Int16x8(0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0, 0xFFFF, 0)
            );
            B = SIMD.Int32x4.fromInt16x8Bits(B);

            Aprod = SIMD.Int32x4.mul(
                A,
                SIMD.Int32x4.swizzle(A, 2, 3, 1, 0)
            );
            Bprod = SIMD.Int32x4.mul(
                B,
                SIMD.Int32x4.swizzle(B, 2, 3, 1, 0)
            );

            // XXX: forgetting the 'var' on everything
            RawTerms = SIMD.Int32x4.shuffle(Aprod, Bprod, 0, 1, 4, 5);
            MidTerms = SIMD.Int32x4.shuffle(Aprod, Bprod, 2, 3, 6, 7);
            MidTermsL = SIMD.Int32x4.shiftLeftByScalar(MidTerms, 16);
            MidTermsR = SIMD.Int32x4.shiftRightLogicalByScalar(MidTerms, 16);

            ToAddOne = SIMD.Int32x4.shuffle(MidTermsL, MidTermsR, 0, 4, 2, 6);
            ToAddTwo = SIMD.Int32x4.shuffle(MidTermsL, MidTermsR, 1, 5, 3, 7);

            acc = SIMD.Int32x4.add(RawTerms, ToAddOne);
    carries = SIMD.Int32x4.or(
        SIMD.Int32x4.and(
            SIMD.Int32x4.greaterThan(ToAddOne, zero),
            SIMD.Int32x4.lessThan(acc, RawTerms)
        ),
        SIMD.Int32x4.and(
            SIMD.Int32x4.lessThan(ToAddOne, zero),
            SIMD.Int32x4.greaterThan(acc, RawTerms)
        )
    );
    carries = SIMD.Int32x4.select(
        carries,
        low_ones,
        zero
    );
    carries = SIMD.Int32x4.swizzle(carries, 1, 0, 3, 2);
    RawTerms = SIMD.Int32x4.add(
        acc,
        carries
    );

            acc = SIMD.Int32x4.add(RawTerms, ToAddTwo);
    carries = SIMD.Int32x4.or(
        SIMD.Int32x4.and(
            SIMD.Int32x4.greaterThan(ToAddTwo, zero),
            SIMD.Int32x4.lessThan(acc, RawTerms)
        ),
        SIMD.Int32x4.and(
            SIMD.Int32x4.lessThan(ToAddTwo, zero),
            SIMD.Int32x4.greaterThan(acc, RawTerms)
        )
    );
    carries = SIMD.Int32x4.select(
        carries,
        low_ones,
        zero
    );
    carries = SIMD.Int32x4.swizzle(carries, 1, 0, 3, 2);
    RawTerms = SIMD.Int32x4.add(
        acc,
        carries
    );

            Bj = RawTerms;

            // ADD.
            acc = SIMD.Int32x4.add(Bj, S0p0);
    carries = SIMD.Int32x4.or(
        SIMD.Int32x4.and(
            SIMD.Int32x4.greaterThan(S0p0, zero),
            SIMD.Int32x4.lessThan(acc, Bj)
        ),
        SIMD.Int32x4.and(
            SIMD.Int32x4.lessThan(S0p0, zero),
            SIMD.Int32x4.greaterThan(acc, Bj)
        )
    );
    carries = SIMD.Int32x4.select(
        carries,
        low_ones,
        zero
    );
    carries = SIMD.Int32x4.swizzle(carries, 1, 0, 3, 2);
    Bj = SIMD.Int32x4.add(
        acc,
        carries
    );


            // XOR.
            Bj = SIMD.Int32x4.xor(Bj, S1p1);

            // Store Bj back.
            SIMD.Int32x4.store(pwxblock, 2 * j * this.PWXSIMPLE, Bj);
        }
    }
}
