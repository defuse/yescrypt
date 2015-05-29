<?php

/*
 * This is a VERY SLOW reference implementation of plain scrypt. Don't use it!
 *
 * This software is Copyright (c) 2015 Taylor Hornby <havoc@defuse.ca>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * LIMITATIONS:
 *  - On 32-bit PHP with non-IEEE 754 floating point, the results may not be
 *    correct, as for fast addition modulo 2^32 PHP, intermediate values above
 *    2^31 - 1 are floats.
 *  - The same problem on 32-bit PHP creates a side channel that could leak
 *    a fast password verifier to an attacker on a shared system.
 *  - N must be <= 2^31 - 1, so the highest supported value is N = 2^30.
 */

class YescryptException extends Exception { }

abstract class Yescrypt {

    public static function calculate($password, $salt, $lgN, $r, $p, $dkLen)
    {
        if ($lgN < 0 || $lgN > 30 || $lgN > 128 * $r / 8) {
            throw new YescryptException("lgN is negative or too big.");
        }

        $bytes = hash_pbkdf2('sha256', $password, $salt, 1, $p * 128 * $r, true);
    
        $B = array();
        for ($i = 0; $i <= $p - 1; $i++) {
            $B[$i] = str_split( substr($bytes, $i * 128 * $r, 128 * $r), 64 );
        }
    
        for ($i = 0; $i <= $p - 1; $i++) {
            $B[$i] = self::scryptROMix($r, $B[$i], 1 << $lgN);
        }
    
        $new_salt = "";
        for ($i = 0; $i <= $p - 1; $i++) {
            $new_salt .= implode('', $B[$i]);
        }
    
        return hash_pbkdf2('sha256', $password, $new_salt, 1, $dkLen, true);
    }

    /*
     * The scryptROMix function.
     * $r is the block size parameter.
     * $B is a 2*r entry array of 64-byte strings.
     * $N is the CPU/memory cost parameter. Must be a power of two larger than 1.
     */
    public static function scryptROMix($r, $B, $N)
    {
        if (!is_int($r) || $r <= 0 || !is_array($B) || count($B) != 2*$r || !is_int($N) || $N <= 1) {
            throw new YescryptException("bad parameters to scryptROMix");
        }
    
        $v = array();
        $x = $B;
        for ($i = 0; $i <= $N - 1; $i++) {
            $v[$i] = $x;
            $x = self::scryptBlockMix($r, $x);
        }
    
        $t = array();
        for ($i = 0; $i <= $N - 1; $i++) {
            // On 32-bit PHP, integerify() can return a negative value here, but
            // the & will do the right thing (% $N won't).
            $j = self::integerify($r, $x) & ($N - 1);
            for ($k = 0; $k <= 2*$r - 1; $k++) {
                $t[$k] = $x[$k] ^ $v[$j][$k];
            }
            $x = self::scryptBlockMix($r, $t);
        }
    
        return $x;
    }

    /*
     * Interprets $B as a little-endian 32-bit integer.
     * NOTE: This may return negative values on 32-bit PHP!
     */
    public static function integerify($r, $B)
    {
        $last_block = $B[2*$r - 1];
        return unpack("V", $last_block)[1];
    }

    /*
     * The scryptBlockMix function.
     * $r is the block size parameter.
     * $B is a 2*r entry array of 64-byte strings.
     * Returns a 2*r entry array of 64-byte strings.
     */
    public static function scryptBlockMix($r, $B)
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
        return $y;
    }

    public static function salsa20_8_core_binary($in)
    {
        if (self::our_strlen($in) != 64) {
            throw new YescryptException("Block passed to salsa20_8_core_binary is not 64 bytes");
        }
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

