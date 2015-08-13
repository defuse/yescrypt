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

    // Assumed by the acc = SIMD.Int32x4.add(, );
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, ),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32-)
    );
     = SIMD.Int32x4.xor(, acc);
 macro.
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

yescrypt.pwxform = function (pwxblock, sbox) {
    // TODO: SIMD implementation of pwxform.
}
