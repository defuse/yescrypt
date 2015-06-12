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
 * Compatibility: 64-bit PHP version 5.4 or greater.
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

/* Flags. */
define('YESCRYPT_RW', 1);
define('YESCRYPT_WORM', 2);

class YescryptException extends Exception { }

abstract class Yescrypt {

    public static function calculate($password, $salt, $N, $r, $p, $t, $g, $flags, $dkLen)
    {
        if (PHP_INT_SIZE < 8) {
            throw new YescryptException("This implementation requires 64-bit integers.");
        }

        if ($flags & ~(YESCRYPT_RW | YESCRYPT_WORM)) {
            throw new YescryptException("Unknown flags.");
        }

        if ($flags === 0 && $t !== 0) {
            throw new YescryptException("Can't use t > 0 without flags.");
        }

        if ($r * $p >= 1 << 30) {
            throw new YescryptException("r * p is too big.");
        }

        if (($N & ($N - 1)) !== 0) {
            throw new YescryptException("N is not a power of two.");
        }

        if ($N < 1) {
            throw new YescryptException("N is too small.");
        }

        if ($r < 1) {
            throw new YescryptException("r is too small.");
        }

        if ($p < 1) {
            throw new YescryptException("p is too small.");
        }

        if ($g !== 0) {
            throw new YescryptException("g > 0 is not supported yet.");
        }

        // TODO: finish the range checks (N, + different flag combos)

        // TODO: the YESCRYPT_RW stuff for large N/p? (see scrypt-ref.c)

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
    
        $new_salt = "";
        for ($i = 0; $i <= $p - 1; $i++) {
            $new_salt .= implode('', $B[$i]);
        }

        $result = hash_pbkdf2('sha256', $password, $new_salt, 1, $dkLen, true);

        if ($flags !== 0 && $dkLen < 32) {
            $huh = hash_pbkdf2('sha256', $password, $new_salt, 1, 32, true);
        } else {
            $huh = substr($result, 0, 32);
        }
    
        if ($flags !== 0) {
            $clientkey = hash_hmac('sha256', "Client Key", $huh, true);
            $storedkey = hash('sha256', $clientkey, true);
            for ($i = 0; $i < min(32, $dkLen); $i++) {
                $result[$i] = $storedkey[$i];
            }
        }

        return $result;
    }

    public static function fNloop($N, $t, $flags)
    {
        if (($flags & YESCRYPT_RW) !== 0) {
            switch ($t) {
                case 0:
                    return floor(($N + 2) / 3);
                case 1:
                    return floor((2 * $N + 2) / 3);
                default:
                    return ($t - 1) * $N;
            }
        } elseif (($flags & YESCRYPT_WORM) !== 0) {
            switch ($t) {
                case 0:
                    return $N;
                case 1:
                    return $N + floor( ($N + 1) / 2 );
                default:
                    return $t * $N;
            }
        } else {
            return $N;
        }
        // We've omitted the rounding up to the next even integer here.
        // That gets done in sMix().
    }

    public static function p2floor($x)
    {
        while (($y = $x & ($x - 1)) !== 0) {
            $x = $y;
        }
        return $x;
    }

    public static function wrap($x, $i)
    {
        $n = self::p2floor($i);
        return ($x & ($n - 1)) + ($i - $n);
    }

    public static function sMix($N, $r, $t, $p, & $pbkdf2_blocks, $flags)
    {
        $sboxes = array();
        $V = array();
        $output = null;

        $n = floor($N / $p);
        $Nloop_all = self::fNloop($n, $t, $flags);
        if (($flags & YESCRYPT_RW) !== 0) {
            $Nloop_rw = (int)floor($Nloop_all / $p);
        } else { 
            $Nloop_rw = 0;
        }
        $n = $n - ($n & 1);
        $Nloop_all = $Nloop_all + ($Nloop_all & 1);
        $Nloop_rw = $Nloop_rw - ($Nloop_rw & 1);
        for ($i = 0; $i < $p; $i++) {
            $v = $i * $n;
            if ($i === $p - 1) {
                $n = $N - $v;
            }
            $w = $v + $n - 1;
            $sboxes[$i] = null;
            if (($flags & YESCRYPT_RW) !== 0) {
                $x = array($pbkdf2_blocks[$i][0], $pbkdf2_blocks[$i][1]);
                self::SMix1(1, $x, YESCRYPT_SBYTES/128, $sboxes[$i], $flags & ~YESCRYPT_RW, null);
                for ($k = 0; $k < count($sboxes[$i]); $k++) {
                    $sboxes[$i][$k] = implode($sboxes[$i][$k]);
                }
                $sboxes[$i] = implode($sboxes[$i]);
                $pbkdf2_blocks[$i][0] = $x[0];
                $pbkdf2_blocks[$i][1] = $x[1];
            }
            self::SMix1($r, $pbkdf2_blocks[$i], $n, $output, $flags, $sboxes[$i]);
            for ($j = $v; $j <= $w; $j++) {
                $V[$j] = $output[$j - $v];
            }
            self::SMix2($r, $pbkdf2_blocks[$i], self::p2floor($n), $Nloop_rw, $output, $flags, $sboxes[$i]);
            for ($j = $v; $j <= $w; $j++) {
                $V[$j] = $output[$j - $v];
            }
        }
        for ($i = 0; $i < $p; $i++) {
            self::SMix2($r, $pbkdf2_blocks[$i], $N, $Nloop_all - $Nloop_rw, $V, $flags & ~YESCRYPT_RW, $sboxes[$i]);
        }
    }

    public static function sMix1($r, & $input_block, $N, & $out_seq_write_memory, $flags, $sbox)
    {
        $x = $input_block;

        self::simd_shuffle($x);

        $v = array();
        for ($i = 0; $i < $N; $i++) {
            $v[$i] = $x;
            if (false) {
                // TODO: ROM support
            } elseif (($flags & YESCRYPT_RW) !== 0 && $i > 1) {
                $j = self::wrap(self::integerify($r, $x), $i);
                for ($k = 0; $k < 2 * $r; $k++) {
                    $x[$k] ^= $v[$j][$k];
                }
            }
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

        for ($i = 0; $i < $Nloop; $i++) {
            if (false) {
                // TODO: ROM support
            } else {
                $j = self::integerify($r, $x) & ($N - 1);
                for ($k = 0; $k < 2 * $r; $k++) {
                    $x[$k] ^= $v[$j][$k];
                }
                if (($flags & YESCRYPT_RW) !== 0) {
                    $v[$j] = $x;
                }
            }
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

        $r1 = (int)floor(128 * $r / YESCRYPT_PWXBYTES);
        $X = substr($flat, ($r1 - 1) * YESCRYPT_PWXBYTES, YESCRYPT_PWXBYTES);
        for ($i = 0; $i < $r1; $i++) {
            if ($r1 > 1) {
                $X ^= substr($flat, $i * YESCRYPT_PWXBYTES, YESCRYPT_PWXBYTES);
            }
            self::pwxform($X, $sbox);
            for ($j = 0; $j < YESCRYPT_PWXBYTES; $j++) {
                $flat[$i * YESCRYPT_PWXBYTES + $j] = $X[$j];
            }
        }

        $i = (int)floor(($r1 - 1) * YESCRYPT_PWXBYTES / 64);

        $Bi = substr($flat, $i * 64, 64);
        $Bi = self::salsa20_8_core_binary($Bi);
        for ($j = 0; $j < 64; $j++) {
            $flat[$i * 64 + $j] = $Bi[$j];
        }

        $Bim1 = $Bi;
        for ($i = $i + 1; $i < 2 * $r; $i++) {
            $Bi = substr($flat, $i * 64, 64);
            $Bim1 = self::salsa20_8_core_binary($Bi ^ $Bim1);
            for ($j = 0; $j < 64; $j++) {
                $flat[$i * 64 + $j] = $Bim1[$j];
            }
        }
        
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

        $LO = 0;
        $HI = 1;

        for ($i = 0; $i < YESCRYPT_PWXROUNDS; $i++) {
            for ($j = 0; $j < YESCRYPT_PWXGATHER; $j++) {
                $xl = $ints[2 * $j * YESCRYPT_PWXSIMPLE + $LO];
                $xh = $ints[2 * $j * YESCRYPT_PWXSIMPLE + $HI];
                $p0 = (int)floor(($xl & YESCRYPT_SMASK) / (YESCRYPT_PWXSIMPLE * 8));
                $p1 = (int)floor(($xh & YESCRYPT_SMASK) / (YESCRYPT_PWXSIMPLE * 8));

                for ($k = 0; $k < YESCRYPT_PWXSIMPLE; $k++) {
                    $BjkLO = $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $LO];
                    $BjkHI = $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $HI];


                    $S0p0k = $sbox_ints[$p0 * YESCRYPT_PWXSIMPLE + $k];
                    $S1p1k = $sbox_ints[count($sbox_ints) / 2 + $p1 * YESCRYPT_PWXSIMPLE + $k];

                    // MULTIPLICATION

                    // Even 64-bit PHP can only represent values up to 2^63 - 1.
                    // Anything higher will be converted to float, and we'll
                    // lose precision. So we have to implement 32-to-64
                    // multiplication ourselves.

                    // Naive multiplication algorithm:
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

                    // ADDITION
                    $NBjkLO += $S0p0k & 0xFFFFFFFF;
                    $carry = $NBjkLO >> 32;
                    $NBjkLO &= 0xFFFFFFFF;

                    $NBjkHI = ((($S0p0k >> 32) & 0xFFFFFFFF) +
                              $carry +
                              $NBjkHI) & 0xFFFFFFFF;

                    // XOR
                    $NBjkLO ^= $S1p1k & 0xFFFFFFFF;
                    $NBjkHI ^= ($S1p1k >> 32) & 0xFFFFFFFF;

                    $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $LO] = $NBjkLO;
                    $ints[2 * ($j * YESCRYPT_PWXSIMPLE + $k) + $HI] = $NBjkHI;
                }
            }
        }

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
            throw new YescryptException("Bad block size.");
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
            throw new YescryptException("Bad block size.");
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
        // XXX: for returning more than 32 bits, we'd need to deal with the SIMD
        // shuffling here.
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
            throw new YescryptException("bad parameters to scryptBlockMix");
        }
    
        $x = $B[2*$r - 1];
    
        /* If we don't do this, it will be an associative array, and the implode()
           won't come out in the right order. */
        $y = array_fill(0, 2*$r, 0);
    
        for ($i = 0; $i <= 2*$r - 1; $i++) {
            if (self::our_strlen($B[$i]) != 64) {
                throw new YescryptException("block is not 64 bytes in scryptBlockMix");
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
            throw new YescryptException("Block passed to salsa20_8_core_binary is not 64 bytes");
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
            throw new YescryptException("bad parameters to salsa20_8_core_ints");
        }
    
        $x = array();
        for ($i = 0; $i < 16; $i++) {
            if (!is_int($in[$i]) || !is_int($out[$i])) {
                throw new YescryptException("bad value in array passed to salsa20_8_core_ints");
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
            throw new YescryptException("bad parameters given to R");
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

