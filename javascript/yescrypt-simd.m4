/*
 * This file must be loaded *after* yescrypt.js.
 * It replaces the implementations salsa20_8 and pwxform with SIMD versions.
 */

// TODO: we should check if SIMD is available and automatically replace if so.

define(`ARX',
    acc = SIMD.Int32x4.add($2, $3);
    acc = SIMD.Int32x4.or(
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

    // Assumed by the ARX macro.
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

yescrypt.pwxform = function (pwxblock, sbox) {
    // TODO: SIMD implementation of pwxform.
}
