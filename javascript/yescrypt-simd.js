
/*
 * This file must be loaded *after* yescrypt.js.
 * It replaces the implementations salsa20_8 and pwxform with SIMD versions.
 */

// TODO: we should check if SIMD is available and automatically replace if so.

// TODO: inline this stuff.
yescrypt.ARX = function (dest, v1, v2, rot) {
    // TODO: how does this overflow?
    // v1 + v2
    var acc = SIMD.Int32x4.add(v1, v2);
    // R(v1 + v2, rot)
    acc = SIMD.Int32x4.or(
            SIMD.Int32x4.shiftLeftByScalar(acc, rot),
            SIMD.Int32x4.shiftRightLogicalByScalar(acc, 32 - rot)
    );
    // dest ^ R(v1 + v2, rot)
    return SIMD.Int32x4.xor(dest, acc);
}

yescrypt.salsa20_8 = function (cell) {
    // TODO: SIMD implementation of salsa20_8

    var X0 = SIMD.Int32x4.load(cell, 0);
    var X1 = SIMD.Int32x4.load(cell, 4);
    var X2 = SIMD.Int32x4.load(cell, 8);
    var X3 = SIMD.Int32x4.load(cell, 12);

    // XXX for lack of a better way to copy SIMD vectors...
    var OrigX0 = SIMD.Int32x4.load(cell, 0);
    var OrigX1 = SIMD.Int32x4.load(cell, 4);
    var OrigX2 = SIMD.Int32x4.load(cell, 8);
    var OrigX3 = SIMD.Int32x4.load(cell, 12);

    // TODO use m4 or something to unroll this loop.
    for (var i = 8; i > 0; i -= 2) {
        // TODO: use m4 or something to make ARX a macro.
        X1 = yescrypt.ARX(X1, X0, X3, 7);
        X2 = yescrypt.ARX(X2, X1, X0, 9);
        X3 = yescrypt.ARX(X3, X2, X1, 13);
        X0 = yescrypt.ARX(X0, X3, X2, 18);

        X1 = SIMD.Int32x4.swizzle(X1, 3, 0, 1, 2);
        X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
        X3 = SIMD.Int32x4.swizzle(X3, 1, 2, 3, 0);

        X3 = yescrypt.ARX(X3, X0, X1, 7);
        X2 = yescrypt.ARX(X2, X3, X0, 9);
        X1 = yescrypt.ARX(X1, X2, X3, 13);
        X0 = yescrypt.ARX(X0, X1, X2, 18);

        X1 = SIMD.Int32x4.swizzle(X1, 1, 2, 3, 0);
        X2 = SIMD.Int32x4.swizzle(X2, 2, 3, 0, 1);
        X3 = SIMD.Int32x4.swizzle(X3, 3, 0, 1, 2);
    }

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
