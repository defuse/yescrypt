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
 *
 */

if (PHP_INT_MAX < 2 * 4294967296) {
    /* We need to take integers up to twice 2^32 then mod them. */
    /* XXX: This might actually work with 32-bit PHP, but we have to check the
        guarantees when numbers up to that value are represented by floats. */
    die('Your integers are too small.');
}

// XXX : error handling

abstract class Scrypt {

    public static function calculate($password, $salt, $N, $r, $p, $dkLen)
    {
        // XXX be more defensive (overflow)
        $bytes = hash_pbkdf2('sha256', $password, $salt, 1, $p * 128 * $r, true);
    
        $B = array();
        for ($i = 0; $i <= $p - 1; $i++) {
            $B[$i] = str_split( substr($bytes, $i * 128 * $r, 128 * $r), 64 );
        }
    
        for ($i = 0; $i <= $p - 1; $i++) {
            $B[$i] = self::scryptROMix($r, $B[$i], $N);
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
        // XXX: upper bound on N (yes it actually matters).
        // XXX: check N is a power of 2.
        // XXX: check the other shit
        if (!is_int($r) || $r <= 0 || !is_array($B) || count($B) != 2*$r || !is_int($N) || $N <= 1) {
            die('Bad parameters');
        }
    
        $v = array();
        $x = $B;
        for ($i = 0; $i <= $N - 1; $i++) {
            $v[$i] = $x;
            $x = self::scryptBlockMix($r, $x);
        }
    
        $t = array();
        for ($i = 0; $i <= $N - 1; $i++) {
            $j = self::integerify($r, $x) % $N; // & ($N - 1);
            for ($k = 0; $k <= 2*$r - 1; $k++) {
                $t[$k] = $x[$k] ^ $v[$j][$k];
            }
            $x = self::scryptBlockMix($r, $t);
        }
    
        return $x;
    }

    public static function integerify($r, $B)
    {
        // XXX: this isn't the full range (doc limitation)
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
            die('Bad parameters');
        }
    
        // XXX: check each one's length.
    
        $x = $B[2*$r - 1];
    
        /* If we don't do this, it will be an associative array, and the implode()
           won't come out in the right order. */
        $y = array_fill(0, 2*$r, 0);
    
        for ($i = 0; $i <= 2*$r - 1; $i++) {
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
        // XXX: check input is 64-byte string.
        $input_ints = array();
        $output_ints = array();
        for ($i = 0; $i < 16; $i++) {
            // XXX slow
            $input_ints[$i] = unpack("V", substr($in, $i*4, 4))[1];
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
            die('Bad parameters');
        }
    
        $x = array();
        for ($i = 0; $i < 16; $i++) {
            if (!is_int($in[$i]) || !is_int($out[$i])) {
                die('Bad parameters');
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
            die('Bad parameters to rotate_int32');
        }
        return (($int << $rot) | (($int >> (32 - $rot)) & (pow(2, $rot) - 1))) & 0xffffffff;
    }
    
}

