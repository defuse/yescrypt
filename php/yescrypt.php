<?php

/*
 * This software is Copyright (c) 2015 Taylor Hornby <havoc@defuse.ca>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Compatibility: 64-bit PHP version 5.5.0 or greater.
 */

/* Tunable. */
define('YESCRYPT_PWXSIMPLE', 2);
define('YESCRYPT_PWXGATHER', 4);
define('YESCRYPT_PWXROUNDS', 6);
define('YESCRYPT_SWIDTH', 8);

/* Don't touch these. */
define('YESCRYPT_PWXBYTES', YESCRYPT_PWXGATHER * YESCRYPT_PWXSIMPLE * 8);
define('YESCRYPT_PWXWORDS', (YESCRYPT_PWXBYTES / 4));
define('YESCRYPT_SBYTES', 2 * (1 << YESCRYPT_SWIDTH) * YESCRYPT_PWXSIMPLE * 8);
define('YESCRYPT_SWORDS', YESCRYPT_SBYTES / 4);
define('YESCRYPT_SMASK', ((1 << YESCRYPT_SWIDTH) - 1) * YESCRYPT_PWXSIMPLE * 8);
define('YESCRYPT_RMIN', (int)floor((YESCRYPT_PWXBYTES + 127) / 128));

/* Flags. Keep these the same as the reference implementation. */
define('YESCRYPT_RW', 1);
define('YESCRYPT_WORM', 2);

abstract class Yescrypt {

    /*
     * WARNING: Calling this function may trigger a memory allocation error.
     * Make sure to set an error handler to detect this case as per
     * http://stackoverflow.com/a/8440791
     */
    public static function calculate($password, $salt, $N, $r, $p, $t, $g, $flags, $dkLen)
    {
        if (PHP_INT_SIZE < 8) {
            throw new Exception("This implementation requires 64-bit integers.");
        }

        if (!is_int($flags) || ($flags & ~(YESCRYPT_RW | YESCRYPT_WORM)) !== 0) {
            throw new InvalidArgumentException("Unknown flags.");
        }

        if (!is_int($N)) {
            throw new InvalidArgumentException("N is not an integer.");
        }
        if (!is_int($r)) {
            throw new InvalidArgumentException("r is not an integer.");
        }
        if (!is_int($p)) {
            throw new InvalidArgumentException("p is not an integer.");
        }

        if (!is_int($t)) {
            throw new InvalidArgumentException("t is not an integer.");
        }

        if (!is_int($g)) {
            throw new InvalidArgumentException("g is not an integer.");
        }

        if (!is_int($dkLen)) {
            throw new InvalidArgumentException("dkLen is not an integer.");
        }

        // If $N is not a power of two, subtracting 1 will leave the leading
        // one unchanged, and thus the & will be non-zero. The other direction
        // is obvious.
        if (($N & ($N - 1)) !== 0) {
            throw new DomainException("N is not a power of two.");
        }

        if ($N <= 1) {
            throw new DomainException("N is too small.");
        }

        if ($r < 1) {
            throw new DomainException("r is too small.");
        }

        if ($p < 1) {
            throw new DomainException("p is too small.");
        }

        if ($g !== 0) {
            throw new DomainException("g > 0 is not supported yet.");
        }

        // The largest value computed is 128 * $r * $p, and we want that to fit
        // into one of PHP's integers. Let's check if it overflows into a float.
        if (!is_int($r * $p * 128)) {
            throw new DomainException("r * p is too big.");
        }

        if ($flags === 0 && $t !== 0) {
            throw new DomainException("Can't use t > 0 without flags.");
        }

        // NOTE: We don't check an upper bound on $N here, since it is simpler
        // to just check for overflow after computing fNloop.

        if ( ($flags & YESCRYPT_RW) !== 0 && $p >= 1 && (int)floor($N / $p) >= 0x100 && (int)floor($N / $p) * $r >= 0x20000 ) {
            // TODO: implement this (see yescrypt-ref.c in yescrypt_kdf()).
            throw new DomainException("YESCRYPT_PREHASH is not implemented.");
        }

        if ($flags !== 0) {
            // Pre-hash to stop long passwords from being replacable by their
            // SHA256 hash (a quirk of HMAC).
            $password = hash_hmac('sha256', $password, "yescrypt", true);
        }

        $bytes = hash_pbkdf2('sha256', $password, $salt, 1, $p * 128 * $r, true);
    
        $B = array();
        for ($i = 0; $i < $p; $i++) {
            $B[$i] = str_split( substr($bytes, $i * 128 * $r, 128 * $r), 64 );
        }

        if ($flags !== 0) {
            $password = substr($bytes, 0, 32);
        }
    
        if (($flags & YESCRYPT_RW) !== 0) {
            // New yescrypt paralellism (inside this call).
            self::sMix($N, $r, $t, $p, $B, $flags);
        } else {
            // Classic scrypt paralellism.
            for ($i = 0; $i < $p; $i++) {
                $B0 = array($B[$i]);
                self::sMix($N, $r, $t, 1, $B0, $flags);
                $B[$i] = $B0[0];
            }
        }
    
        // DK <-- PBKDF2(P, B, 1, dkLen)
        $new_salt = "";
        for ($i = 0; $i <= $p - 1; $i++) {
            $new_salt .= implode('', $B[$i]);
        }
        // Make sure we get at least 32 bytes.
        $result = hash_pbkdf2('sha256', $password, $new_salt, 1, max($dkLen, 32), true);

        if ($flags !== 0) {
            // This is why we needed at least 32 bytes.
            $client_value = substr($result, 0, 32);

            $clientkey = hash_hmac('sha256', "Client Key", $client_value, true);
            $storedkey = hash('sha256', $clientkey, true);

            // Update the first 32 bytes of the result.
            for ($i = 0; $i < min(32, $dkLen); $i++) {
                $result[$i] = $storedkey[$i];
            }
        }

        // We might have gotten more than we needed to above, so truncate.
        return substr($result, 0, $dkLen);
    }

    public static function fNloop($N, $t, $flags)
    {
        /* +------+-----------------+-----------------+
         * |      | Nloop           |                 |
         * | t    | YESCRYPT_RW     | YESCRYPT_WORM   |
         * +------+-----------------+-----------------+
         * | 0    | (N+2)/3         | N               |
         * | 1    | (2N + 2) / 3    | N + (N + 1) / 2 |
         * | > 1  | (t - 1)*N       | t*N             |
         * +------+-----------------+-----------------+
         */
        if (($flags & YESCRYPT_RW) !== 0) {
            // First column.
            switch ($t) {
                case 0:
                    return (int)floor(($N + 2) / 3);
                case 1:
                    return (int)floor((2 * $N + 2) / 3);
                default:
                    return ($t - 1) * $N;
            }
        } elseif (($flags & YESCRYPT_WORM) !== 0) {
            // Second column.
            switch ($t) {
                case 0:
                    return $N;
                case 1:
                    return $N + (int)floor( ($N + 1) / 2 );
                default:
                    return $t * $N;
            }
        } else {
            // Without any flags, it's the same as scrypt.
            return $N;
        }
        /*
         * Note that Nloop is supposed to be rounded up to the next even
         * integer, to simplify optimized implementations. We don't do that here
         * in this function, because it happens in sMix().
         */
    }

    /*
     * Finds the largest power of 2 less than or equal to $x.
     */
    public static function p2floor($x)
    {
        // p2floor(i) = 2^(floor(log_2(i))).
        while (($y = $x & ($x - 1)) !== 0) {
            $x = $y;
        }
        return $x;
    }

    /*
     * Wraps $x to a value between 0 and $i - 1 (inclusive).
     */
    public static function wrap($x, $i)
    {
        // Wrap(x, i) = (x mod p2floor(i)) + (i - p2floor(i))
        $n = self::p2floor($i);
        return ($x & ($n - 1)) + ($i - $n);
    }

    public static function sMix($N, $r, $t, $p, & $pbkdf2_blocks, $flags)
    {
        $sboxes = array();
        $V = array();
        $output = null;

        // n <- N / p
        $n = (int)floor($N / $p);
        // Nloop_all <- fNloop(n, t, flags)
        $Nloop_all = self::fNloop($n, $t, $flags);

        // if YESCRYPT_RW flag is set
        if (($flags & YESCRYPT_RW) !== 0) {
            // Nloop_rw <- Nloop_all / p
            $Nloop_rw = (int)floor($Nloop_all / $p);
        } else { 
            // Nloop_rw <- 0
            $Nloop_rw = 0;
        }

        // n <- n - (n mod 2)
        $n = $n - ($n & 1);

        // In fNloop, we noted that the spec says to round up to the next
        // highest even integer. We didn't do that in fNloop, because we do it
        // right here:
        // Nloop_all <- Nloop_all + (Nloop_all mod 2)
        $Nloop_all = $Nloop_all + ($Nloop_all & 1);

        // Nloop_rw <- Nloop_rw - (Nloop_rw mod 2)
        $Nloop_rw = $Nloop_rw - ($Nloop_rw & 1);

        // Check if Nloop_all overflowed.
        if (!is_int($Nloop_all)) {
            throw new DomainException("The value of Nloop_all is too big.");
        }

        // for i = 0 to p - 1 do
        for ($i = 0; $i < $p; $i++) {
            // v <- in
            $v = $i * $n;
            // if i = p - 1
            if ($i === $p - 1) {
                // n <- N - v
                $n = $N - $v;
            }
            // w <- v + n - 1
            $w = $v + $n - 1;

            // We don't need to worry about overflow in the lines above, because
            // all the values are <= $N, which we know fits into an integer.

            // Initialize $sboxes[$i] to null, because SMix1 and SMix2 will use
            // pwxform instead of salsa20/8 if and only if we set it to
            // something not-null.
            $sboxes[$i] = null;

            // if YESCRYPT_RW flag is set
            if (($flags & YESCRYPT_RW) !== 0) {
                // SMix1_1(B_i, Sbytes/128, S_i, flags excluding YESCRYPT_RW)

                // For r=1, we need the first two 64-byte blocks.
                $x = array($pbkdf2_blocks[$i][0], $pbkdf2_blocks[$i][1]);
                self::SMix1(1, $x, YESCRYPT_SBYTES/128, $sboxes[$i], $flags & ~YESCRYPT_RW, null);

                // Now, we've used SMix1 to construct the sboxes for further
                // invocation. But that's in array-of-array form, and we need to
                // flatten it out so we can use it as an sbox.
                for ($k = 0; $k < count($sboxes[$i]); $k++) {
                    $sboxes[$i][$k] = implode($sboxes[$i][$k]);
                }
                $sboxes[$i] = implode($sboxes[$i]);

                // We copied the first two 64-byte blocks out. SMix1 changed
                // them, so we need to write them back.
                $pbkdf2_blocks[$i][0] = $x[0];
                $pbkdf2_blocks[$i][1] = $x[1];
            }

            // SMix1_r(B_i, n, V_{v...w}, flags)
            self::SMix1($r, $pbkdf2_blocks[$i], $n, $output, $flags, $sboxes[$i]);
            for ($j = $v; $j <= $w; $j++) {
                $V[$j] = $output[$j - $v];
            }

            // SMix2_r(B_i, p2floor(n), Nloop_rw, V_{v...w}, flags)
            self::SMix2($r, $pbkdf2_blocks[$i], self::p2floor($n), $Nloop_rw, $output, $flags, $sboxes[$i]);
            for ($j = $v; $j <= $w; $j++) {
                $V[$j] = $output[$j - $v];
            }
        }

        // for i = 0 to p - 1
        for ($i = 0; $i < $p; $i++) {
            // SMix2_r(B_i, N, Nloop_all - Nloop_rw, V, flags excluding YESCRYPT_RW)
            self::SMix2($r, $pbkdf2_blocks[$i], $N, $Nloop_all - $Nloop_rw, $V, $flags & ~YESCRYPT_RW, $sboxes[$i]);
        }
    }

    public static function sMix1($r, & $input_block, $N, & $out_seq_write_memory, $flags, $sbox)
    {
        $x = $input_block;

        self::simd_shuffle($x);

        $v = array();
        // for i = 0 to N - 1 do
        for ($i = 0; $i < $N; $i++) {
            // V_i = X
            $v[$i] = $x;
            // if (have ROM) and ( (i /\ 1) != 0 )
            if (false) {
                // TODO: ROM support

            // else if (YESCRYPT_RW flag is set) and (i > 1)
            } elseif (($flags & YESCRYPT_RW) !== 0 && $i > 1) {
                // j <- Wrap(Integerify(X), i)
                if ($i >= 1 << 30) {
                    // The result of integerify is taken modulo p2floor($i).
                    // Since our integerify only returns a 32-bit signed result,
                    // check if not having the full 64-bit implementation would
                    // affect the result.
                    throw new DomainException("Value of i is too big for our integerify(), in sMix1.");
                }
                $j = self::wrap(self::integerify($r, $x), $i);
                // X <- X XOR V_j
                for ($k = 0; $k < 2 * $r; $k++) {
                    $x[$k] ^= $v[$j][$k];
                }
            }

            // X <- H(X), where H is either salsa20/8 or pwxform, depending on
            // flags.
            if (is_null($sbox)) {
                self::blockmix_salsa8($r, $x);
            } else {
                self::blockmix_pwxform($r, $x, $sbox);
            }
        }

        self::simd_unshuffle($x);

        $input_block = $x;
        $out_seq_write_memory = $v;
    }

    public static function sMix2($r, & $input_block, $N, $Nloop, & $seq_write_memory, $flags, $sbox)
    {
        $x = $input_block;
        $v = $seq_write_memory;

        self::simd_shuffle($x);

        // for i = 0 to Nloop - 1 do
        for ($i = 0; $i < $Nloop; $i++) {
            // if (have ROM) and ( (i /\ 1) != 0 )
            if (false) {
                // TODO: ROM support
            } else {
                // j <- Integerify(X) mod N
                if ($N >= 1 << 30) {
                    // integerify is supposed to return a 64-bit integer, but
                    // ours returns a 32-bit signed integer. If this would
                    // affect the result, throw an exception.
                    throw new DomainException("We don't support values of N (in sMix2) that big.");
                }
                $j = self::integerify($r, $x) & ($N - 1);
                // X <- X XOR V_j
                for ($k = 0; $k < 2 * $r; $k++) {
                    $x[$k] ^= $v[$j][$k];
                }
                // if YESCRYPT_RW flag is set
                if (($flags & YESCRYPT_RW) !== 0) {
                    // V_j <- X
                    $v[$j] = $x;
                }
            }
            // X <- H(X), where H is either salsa20/8 or pwxform depending on
            // flags.
            if (is_null($sbox)) {
                self::blockmix_salsa8($r, $x);
            } else {
                self::blockmix_pwxform($r, $x, $sbox);
            }
        }

        self::simd_unshuffle($x);

        $input_block = $x;
        $seq_write_memory = $v;
    }

    public static function blockmix_pwxform($r, & $B, $sbox)
    {
        $flat = implode('', $B);

        // r1 <- 128 * r / PWXbytes
        $r1 = (int)floor(128 * $r / YESCRYPT_PWXBYTES);

        // X <- B'_{r_1 - 1}
        $X = substr($flat, ($r1 - 1) * YESCRYPT_PWXBYTES, YESCRYPT_PWXBYTES);

        // for i = 0 to r_1 - 1 do
        for ($i = 0; $i < $r1; $i++) {
            // if r_1 > 1
            if ($r1 > 1) {
                // X <- X XOR B'_i
                $X ^= substr($flat, $i * YESCRYPT_PWXBYTES, YESCRYPT_PWXBYTES);
            }
            // X <- pwxform(X)
            self::pwxform($X, $sbox);
            // B'_i <- X
            for ($j = 0; $j < YESCRYPT_PWXBYTES; $j++) {
                $flat[$i * YESCRYPT_PWXBYTES + $j] = $X[$j];
            }
        }

        // i = floor( (r_1 - 1) * PWXbytes / 64 )
        $i = (int)floor(($r1 - 1) * YESCRYPT_PWXBYTES / 64);

        // B_i <- H(B_i) (where H is salsa20/8)
        $Bi = substr($flat, $i * 64, 64);
        $Bi = self::salsa20_8_core_binary($Bi);
        for ($j = 0; $j < 64; $j++) {
            $flat[$i * 64 + $j] = $Bi[$j];
        }

        // for i = i + 1 to 2*r - 1
        $Bim1 = $Bi; // B_{i-1}
        for ($i = $i + 1; $i < 2 * $r; $i++) {
            // B_i <- H(B_i XOR B_{i-1})
            // Instead of re-reading B_{i-1} we just save it from the last
            // iteration.
            $Bi = substr($flat, $i * 64, 64);
            $Bim1 = self::salsa20_8_core_binary($Bi ^ $Bim1);
            for ($j = 0; $j < 64; $j++) {
                $flat[$i * 64 + $j] = $Bim1[$j];
            }
        }
        
        // Return the result.
        $B = str_split($flat, 64);
    }

    public static function pwxform(& $b, $sbox)
    {
        // Split into 32-bit integers for easy access.
        $ints = array();
        $split = str_split($b, 4);
        for ($i = 0; $i < count($split); $i++) {
            // XXX 64-bit only (negative values above 2^31)
            $ints[$i] = unpack("V", $split[$i])[1];
        }

        // Split $sbox into 64-bit integers.
        $sbox_ints = array();
        $split = str_split($sbox, 8);
        for ($i = 0; $i < count($split); $i++) {
            // XXX: 64-bit only.
            // We can't use "P" here because it's only in PHP 5.6.
            $sbox_ints[$i] = unpack("V", substr($split[$i], 0, 4))[1];
            $sbox_ints[$i] |= unpack("V", substr($split[$i], 4, 4))[1] << 32;
        }

        // Instead of splitting into 64-bit integers and then using shifts to
        // get the high and low parts, we split into 32-bit integers and will
        // use an offset to get the high and low parts. This means that all of
        // our indices into $ints will have to be multiplied by 2, and we either
        // add 0 for the low part or 1 for the high part (little endian).
        $LO = 0;
        $HI = 1;

        // NOTE: There is some inconsistency in the original specification. The
        // 'for' loop upper bounds are written as inclusive, but checking the
        // reference implementation, they are actually exclusive here.
        // Therefore, in the comments, I have added "- 1" to the upper bound.

        // for i = 0 to PWXrounds - 1 do
        for ($i = 0; $i < YESCRYPT_PWXROUNDS; $i++) {
            // for j = 0 to PWXgather - 1 do
            for ($j = 0; $j < YESCRYPT_PWXGATHER; $j++) {

                // lo(B_j,0)
                $xl = $ints[2 * $j * YESCRYPT_PWXSIMPLE + $LO];
                // hi(B_j,0)
                $xh = $ints[2 * $j * YESCRYPT_PWXSIMPLE + $HI];

                // p0 <- (lo(B_j,0) ^ Smask) / (PWXsimple * 8)
                $p0 = (int)floor(($xl & YESCRYPT_SMASK) / (YESCRYPT_PWXSIMPLE * 8));
                // p1 <- (hi(B_j,0) ^ Smask) / (PWXsimple * 8)
                $p1 = (int)floor(($xh & YESCRYPT_SMASK) / (YESCRYPT_PWXSIMPLE * 8));

                // for k = 0 to PWXsimple - 1 do
                for ($k = 0; $k < YESCRYPT_PWXSIMPLE; $k++) {
                    // lo(B_j,k)
                    $BjkLO = $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $LO];
                    // hi(B_j,k)
                    $BjkHI = $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $HI];

                    // S0_p0,k
                    $S0p0k = $sbox_ints[$p0 * YESCRYPT_PWXSIMPLE + $k];
                    // S1_p1,k
                    $S1p1k = $sbox_ints[count($sbox_ints) / 2 + $p1 * YESCRYPT_PWXSIMPLE + $k];

                    // B_j,k <- (hi(B_j,k) * lo(B_j,k) + S0_p0,k) XOR S1_p1,k

                    // MULTIPLICATION: hi(B_j,k) * lo(B_j,k).

                    // Even 64-bit PHP can only represent values up to 2^63 - 1.
                    // Anything higher will be converted to float, and we'll
                    // lose precision. So we have to implement 32-to-64
                    // multiplication ourselves.

                    // Naive multiplication algorithm:
                    // A = 2^16 * h(A) + l(A)
                    // B = 2^16 * h(B) + l(B)
                    // A * B = (2^16 * h(A) + l(A))  *  (2^16 * h(B) + l(B))
                    // A * B = 2^32 h(A) h(B) + 2^16 h(A) l(B) + 2^16 h(B) l(A) + l(A) l(B)

                    $hA = ($BjkHI >> 16) & 0xFFFF;
                    $lA = $BjkHI & 0xFFFF;
                    $hB = ($BjkLO >> 16) & 0xFFFF;
                    $lB = $BjkLO & 0xFFFF;

                    $NBjkLO = 0;
                    $NBjkHI = 0;

                    // Add in the first term: 2^32 h(A) h(B)
                    $NBjkHI += $hA * $hB;

                    // Add in the remaining terms: 2^16 h(A) l(B) + 2^16 h(B) + l(A) l(B)
                    // This value won't be more than 2^49, so we don't have to
                    // worry about overflow on 64-bit php. (XXX: 64-bit only).
                    $acc = (($hA * $lB) << 16) + (($hB * $lA) << 16) + ($lA * $lB);
                    // It's zero, so there will be no carry.
                    $NBjkLO += $acc & 0xFFFFFFFF;
                    $NBjkHI += ($acc >> 32) & 0xFFFFFFFF;

                    // This shouldn't actually be necessary, but just in case.
                    $NBjkHI &= 0xFFFFFFFF;

                    // ADDITION: ... + S0_p0,k
                    $NBjkLO += $S0p0k & 0xFFFFFFFF;
                    $carry = $NBjkLO >> 32;
                    $NBjkLO &= 0xFFFFFFFF;

                    $NBjkHI = ((($S0p0k >> 32) & 0xFFFFFFFF) +
                              $carry +
                              $NBjkHI) & 0xFFFFFFFF;

                    // XOR: ... XOR S1_p1,k
                    $NBjkLO ^= $S1p1k & 0xFFFFFFFF;
                    $NBjkHI ^= ($S1p1k >> 32) & 0xFFFFFFFF;

                    // Save back into B_j,k.
                    $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $LO] = $NBjkLO;
                    $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $HI] = $NBjkHI;
                }
            }
        }

        // Return the result by modifying the input parameter.
        $new_b = "";
        for ($i = 0; $i < count($ints); $i++) {
            $new_b .= pack("V", $ints[$i]);
        }

        $b = $new_b;
    }

    public static function simd_shuffle(& $x)
    {
        for ($i = 0; $i < count($x); $i++) {
            $x[$i] = self::simd_shuffle_block($x[$i]);
        }
    }

    public static function simd_unshuffle(& $x)
    {
        for ($i = 0; $i < count($x); $i++) {
            $x[$i] = self::simd_unshuffle_block($x[$i]);
        }
    }

    public static function simd_shuffle_block($b)
    {
        if (self::our_strlen($b) !== 64) {
            throw new DomainException("Bad block size.");
        }

        $shuffled = "";
        for ($i = 0; $i < 16; $i++) {
            $shuffled .= substr($b, 4*(($i * 5) % 16), 4);
        }

        return $shuffled;
    }

    public static function simd_unshuffle_block($b)
    {
        if (self::our_strlen($b) !== 64) {
            throw new DomainException("Bad block size.");
        }

        $unshuffled = array_fill(0, 16, null);
        for ($i = 0; $i < 16; $i++) {
            $unshuffled[($i * 5) % 16] = substr($b, 4*$i, 4);
        }
        return implode('', $unshuffled);
    }

    /*
     * Interprets $B as a little-endian 32-bit integer.
     * NOTE: This may return negative values on 32-bit PHP!
     */
    public static function integerify($r, $B)
    {
        /*
         * NOTE: If you're modifying this to return a 64-bit value, remember
         * that $B has been SIMD-shuffled, so you'll have to look at the spec to
         * see which is the correct index of the high part.
         */
        $last_block = $B[2*$r - 1];
        return unpack("V", $last_block)[1];
    }

    /*
     * The scryptBlockMix function.
     * $r is the block size parameter.
     * $B is a 2*r entry array of 64-byte strings.
     * Returns a 2*r entry array of 64-byte strings.
     */
    public static function blockmix_salsa8($r, & $B)
    {
        if (!is_int($r) || $r <= 0 || !is_array($B) || count($B) != 2*$r) {
            throw new DomainException("bad parameters to scryptBlockMix");
        }
    
        $x = $B[2*$r - 1];
    
        /* If we don't do this, it will be an associative array, and the implode()
           won't come out in the right order. */
        $y = array_fill(0, 2*$r, 0);
    
        for ($i = 0; $i <= 2*$r - 1; $i++) {
            if (self::our_strlen($B[$i]) != 64) {
                throw new DomainException("block is not 64 bytes in scryptBlockMix");
            }
            $t = $x ^ $B[$i];
            $x = self::salsa20_8_core_binary($t);
            if ($i % 2 == 0) {
                $y[$i / 2] = $x;
            } else {
                $y[$r + ($i - 1)/2] = $x;
            }
        }
        $B = $y;
    }

    public static function salsa20_8_core_binary($in)
    {
        if (self::our_strlen($in) != 64) {
            throw new DomainException("Block passed to salsa20_8_core_binary is not 64 bytes");
        }

        $in = self::simd_unshuffle_block($in);

        $output_ints = array();
        $input_ints = str_split($in, 4);
        for ($i = 0; $i < 16; $i++) {
            $input_ints[$i] = unpack("V", $input_ints[$i])[1];
            $output_ints[$i] = 0;
        }
        self::salsa20_8_core_ints($input_ints, $output_ints);
        $out = "";
        for ($i = 0; $i < 16; $i++) {
            $out .= pack("V", $output_ints[$i]);
        }

        $out = self::simd_shuffle_block($out);

        return $out;
    }

    /*
     * The reduced-round Salsa20 core function.
     * Both parameters $in and $out must be a 16-entry array of ints.
     * The result is left in $out.
     */
    public static function salsa20_8_core_ints($in, & $out)
    {
        if (!is_array($in) || count($in) != 16 || !is_array($out) || count($out) != 16) {
            throw new DomainException("bad parameters to salsa20_8_core_ints");
        }
    
        $x = array();
        for ($i = 0; $i < 16; $i++) {
            if (!is_int($in[$i]) || !is_int($out[$i])) {
                throw new DomainException("bad value in array passed to salsa20_8_core_ints");
            }
            $x[$i] = $in[$i];
        }
    
        for ($i = 8; $i > 0; $i -= 2) {
             $x[ 4] ^= self::R(($x[ 0]+$x[12]) & 0xffffffff, 7);  $x[ 8] ^= self::R(($x[ 4]+$x[ 0]) & 0xffffffff, 9);
             $x[12] ^= self::R(($x[ 8]+$x[ 4]) & 0xffffffff,13);  $x[ 0] ^= self::R(($x[12]+$x[ 8]) & 0xffffffff,18);
             $x[ 9] ^= self::R(($x[ 5]+$x[ 1]) & 0xffffffff, 7);  $x[13] ^= self::R(($x[ 9]+$x[ 5]) & 0xffffffff, 9);
             $x[ 1] ^= self::R(($x[13]+$x[ 9]) & 0xffffffff,13);  $x[ 5] ^= self::R(($x[ 1]+$x[13]) & 0xffffffff,18);
             $x[14] ^= self::R(($x[10]+$x[ 6]) & 0xffffffff, 7);  $x[ 2] ^= self::R(($x[14]+$x[10]) & 0xffffffff, 9);
             $x[ 6] ^= self::R(($x[ 2]+$x[14]) & 0xffffffff,13);  $x[10] ^= self::R(($x[ 6]+$x[ 2]) & 0xffffffff,18);
             $x[ 3] ^= self::R(($x[15]+$x[11]) & 0xffffffff, 7);  $x[ 7] ^= self::R(($x[ 3]+$x[15]) & 0xffffffff, 9);
             $x[11] ^= self::R(($x[ 7]+$x[ 3]) & 0xffffffff,13);  $x[15] ^= self::R(($x[11]+$x[ 7]) & 0xffffffff,18);
             $x[ 1] ^= self::R(($x[ 0]+$x[ 3]) & 0xffffffff, 7);  $x[ 2] ^= self::R(($x[ 1]+$x[ 0]) & 0xffffffff, 9);
             $x[ 3] ^= self::R(($x[ 2]+$x[ 1]) & 0xffffffff,13);  $x[ 0] ^= self::R(($x[ 3]+$x[ 2]) & 0xffffffff,18);
             $x[ 6] ^= self::R(($x[ 5]+$x[ 4]) & 0xffffffff, 7);  $x[ 7] ^= self::R(($x[ 6]+$x[ 5]) & 0xffffffff, 9);
             $x[ 4] ^= self::R(($x[ 7]+$x[ 6]) & 0xffffffff,13);  $x[ 5] ^= self::R(($x[ 4]+$x[ 7]) & 0xffffffff,18);
             $x[11] ^= self::R(($x[10]+$x[ 9]) & 0xffffffff, 7);  $x[ 8] ^= self::R(($x[11]+$x[10]) & 0xffffffff, 9);
             $x[ 9] ^= self::R(($x[ 8]+$x[11]) & 0xffffffff,13);  $x[10] ^= self::R(($x[ 9]+$x[ 8]) & 0xffffffff,18);
             $x[12] ^= self::R(($x[15]+$x[14]) & 0xffffffff, 7);  $x[13] ^= self::R(($x[12]+$x[15]) & 0xffffffff, 9);
             $x[14] ^= self::R(($x[13]+$x[12]) & 0xffffffff,13);  $x[15] ^= self::R(($x[14]+$x[13]) & 0xffffffff,18);
        }
    
        for ($i = 0; $i < 16; $i++) {
            $out[$i] = ($x[$i] + $in[$i]) & 0xffffffff;
        }
    }

    /*
     * Rotates a PHP integer $int left by $rot as though it were a 32-bit
     * integer. Assumes PHP integers are at least 32 bits.
     */
    public static function R($int, $rot)
    {
        if (!is_int($int) || !is_int($rot) || $rot <= 0 || $rot >= 32) {
            throw new DomainException("bad parameters given to R");
        }
        return (($int << $rot) | (($int >> (32 - $rot)) & (pow(2, $rot) - 1))) & 0xffffffff;
    }

    /*
     * We need these strlen() and substr() functions because when
     * 'mbstring.func_overload' is set in php.ini, the standard strlen() and
     * substr() are replaced by mb_strlen() and mb_substr().
     */
    private static function our_strlen($str)
    {
        if (function_exists('mb_strlen')) {
            $length = mb_strlen($str, '8bit');
            if ($length === FALSE) {
                throw new CannotPerformOperationException();
            }
            return $length;
        } else {
            return strlen($str);
        }
    }
}

