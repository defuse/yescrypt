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

yescrypt.pwxform2 = function (pwxblock, sbox) {
    this.assert(this.PWXSIMPLE == 2)

    var zero = SIMD.Int32x4(0, 0, 0, 0);
    var ones = SIMD.Int32x4(1, 1, 1, 1);
    var low_ones = SIMD.Int32x4(1, 0, 1, 0);
    // Assumed by The ADD---Int64x2 macro. XXX: figure out how to say the macro's name correctly.
    var acc;

    for (var i = 0; i < this.PWXROUNDS; i++) {
        // We do TWO j indexes at a time, because we can fit FOUR 32-bit ints
        // into a SIMD vector.
        for (var j = 0; j < this.PWXGATHER; j += 2) {

            var start = 2 * j * this.PWXSIMPLE;
            var p = SIMD.Int32x4(
                pwxblock[2 * j * this.PWXSIMPLE],
                pwxblock[2 * j * this.PWXSIMPLE + 1],
                pwxblock[2 * (j+1) * this.PWXSIMPLE],
                pwxblock[2 * (j+1) * this.PWXSIMPLE]
            );
            p = SIMD.Int32x4.and(p, SIMD.Int32x4.splat(this.SMASK));
            // Divide by PWXSIMPLE * 8 == 2 * 8 == 16 == 2^4
            p = SIMD.Int32x4.shiftRightLogicalByScalar(p, 4);

            var first = SIMD.Int32x4.load(pwxblock, start);
            var second = SIMD.Int32x4.load(pwxblock, start + 4);
            var B_lows = SIMD.Int32x4.shuffle(first, second, 0, 2, 4, 6);
            var B_highs = SIMD.Int32x4.shuffle(first, second, 1, 3, 5, 7);

            // The shiftRightLogicalByScalar above guarantees the following
            // extractLane() calls return positive numbers.
            var j0S0p0 = SIMD.Int32x4.load(sbox, 2 * (SIMD.Int32x4.extractLane(p, 0) * this.PWXSIMPLE));
            var j1S0p0 = SIMD.Int32x4.load(sbox, 2 * (SIMD.Int32x4.extractLane(p, 2) * this.PWXSIMPLE));
            var j0S1p1 = SIMD.Int32x4.load(sbox, this.SWORDS / 2 + 2 * (SIMD.Int32x4.extractLane(p, 1) * this.PWXSIMPLE));
            var j1S1p1 = SIMD.Int32x4.load(sbox, this.SWOARDS / 2 + 2 * (SIMD.Int32x4.extractLane(p, 3) * this.PWXSIMPLE));

            // MULTIPLY.
            var Ah = SIMD.Int32x4.shiftRightLogicalByScalar(B_highs, 16);
            var Al = SIMD.Int32x4.shiftLeftByScalar(B_highs, 16);
            var Bh = SIMD.Int32x4.shiftRightLogicalByScalar(B_lows, 16);
            var Bl = SIMD.Int32x4.shiftLeftByScalar(B_lows, 16);

            var AhBh = SIMD.Int32x4.mul(Ah, Bh);
            var AhBl = SIMD.Int32x4.mul(Ah, Bl);
            var AlBh = SIMD.Int32x4.mul(Al, Bh);
            var AlBl = SIMD.Int32x4.mul(Al, Bl);

            // Ph = AhBh + (AhBl + AlBh) >> 16.
            var sum = SIMD.Int32x4.add(AhBl, AlBh);
            // Compute the carries.
            var carries = SIMD.Int32x4.or(
                SIMD.Int32x4.and(
                    // We added a positive number...
                    SIMD.Int32x4.greaterThan(AlBh, zero),
                    // ... and the result decreased.
                    SIMD.Int32x4.lessThan(sum, AhBl)
                ),
                // OR,
                SIMD.Int32x4.and(
                    // We added a negative number...
                    SIMD.Int32x4.lessThan(AlBh, zero),
                    // ...and the result increased.
                    SIMD.Int32x4.greaterThan(sum, AhBl)
                )
            );
            carries = SIMD.Int32x4.select(carries, ones, zero);
            carries = SIMD.Int32x4.shiftLeftByScalar(carries, 16);
            sum = SIMD.Int32x4.shiftRightLogicalByScalar(sum, 16);
            sum = SIMD.Int32x4.add(sum, carries);
            var Ph = SIMD.Int32x4.add(AhBh, sum);

            // Pl = (AhBl + AlBh) << 16 + AlBl
            var Pl = SIMD.Int32x4.shiftLeftByScalar(
                // XXX We've already computed this sum above.
                SIMD.Int32x4.add(AhBl, AlBh),
                16
            );
            PlNew = SIMD.Int32x4.add(Pl, AlBl);
            // Compute the carries.
            var carries = SIMD.Int32x4.or(
                SIMD.Int32x4.and(
                    // We added a positive number...
                    SIMD.Int32x4.greaterThan(AlBl, zero),
                    // ... and the result decreased.
                    SIMD.Int32x4.lessThan(PlNew, Pl)
                ),
                // OR,
                SIMD.Int32x4.and(
                    // We added a negative number...
                    SIMD.Int32x4.lessThan(AlBl, zero),
                    // ...and the result increased.
                    SIMD.Int32x4.greaterThan(PlNew, Pl)
                )
            );
            carries = SIMD.Int32x4.select(carries, ones, zero);
            Ph = SIMD.Int32x4.add(Ph, carries);
            Pl = PlNew;

            // ADD.
            var Bj0 = SIMD.Int32x4.shuffle(Pl, Ph, 0, 4, 1, 5);
            var Bj1 = SIMD.Int32x4.shuffle(Pl, Ph, 2, 6, 3, 7);

            acc = SIMD.Int32x4.add(Bj0, j0S0p0);
    carries = SIMD.Int32x4.or(
        SIMD.Int32x4.and(
            SIMD.Int32x4.greaterThan(j0S0p0, zero),
            SIMD.Int32x4.lessThan(acc, Bj0)
        ),
        SIMD.Int32x4.and(
            SIMD.Int32x4.lessThan(j0S0p0, zero),
            SIMD.Int32x4.greaterThan(acc, Bj0)
        )
    );
    carries = SIMD.Int32x4.select(
        carries,
        low_ones,
        zero
    );
    carries = SIMD.Int32x4.swizzle(carries, 1, 0, 3, 2);
    Bj0 = SIMD.Int32x4.add(
        acc,
        carries
    );

            acc = SIMD.Int32x4.add(Bj1, j1S0p0);
    carries = SIMD.Int32x4.or(
        SIMD.Int32x4.and(
            SIMD.Int32x4.greaterThan(j1S0p0, zero),
            SIMD.Int32x4.lessThan(acc, Bj1)
        ),
        SIMD.Int32x4.and(
            SIMD.Int32x4.lessThan(j1S0p0, zero),
            SIMD.Int32x4.greaterThan(acc, Bj1)
        )
    );
    carries = SIMD.Int32x4.select(
        carries,
        low_ones,
        zero
    );
    carries = SIMD.Int32x4.swizzle(carries, 1, 0, 3, 2);
    Bj1 = SIMD.Int32x4.add(
        acc,
        carries
    );


            // XOR.
            Bj0 = SIMD.Int32x4.xor(Bj0, j0S1p1);
            Bj1 = SIMD.Int32x4.xor(Bj1, j1S1p1);

            SIMD.Int32x4.store(pwxblock, start, Bj0);
            SIMD.Int32x4.store(pwxblock, start + 4, Bj1);
        }
    }
}
