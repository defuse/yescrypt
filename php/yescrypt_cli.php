<?php

ini_set('memory_limit', '4G');

/*

    TEST CASES:

        yescrypt: password salt N r p t g flags dkLen
            - try all possible combinations of small parameters/flags

        pwxform B sbox
            - transform some 'random' strings w/ random sbox

        salsa20_8 B
            - transform some 'random' strings


    XXX: don't forget to test bad usage!
 */

require_once('yescrypt.php');

if (count($argv) < 2) {
    die('Not enough arguments.');
}

switch ($argv[1]) {
case "yescrypt":
    if (count($argv) != 11) {
        die('Wrong number of arguments for yescrypt.');
    }
    $result = Yescrypt::calculate(
        hex2bin($argv[2]),  // password
        hex2bin($argv[3]),  // salt
        (int)$argv[4],      // N
        (int)$argv[5],      // r
        (int)$argv[6],      // p
        (int)$argv[7],      // t
        (int)$argv[8],      // g
        (int)$argv[9],      // flags
        (int)$argv[10]      // dkLen
    );
    echo $result;
    break;
case "pwxform":
    if (count($argv) != 4) {
        die('Wrong number of arguments for pwxform.');
    }
    $b = hex2bin($argv[2]);
    $sbox = hex2bin($argv[3]);
    if (strlen($b) !== YESCRYPT_PWXBYTES) {
        die('Input is of incorrect length.');
    }
    if (strlen($sbox) !== YESCRYPT_SBYTES) {
        die('SBox is of incorrect length.');
    }
    $sbox = new SBox($sbox);
    Yescrypt::pwxform($b, $sbox);
    echo $b;
    break;
case "salsa20_8":
    if (count($argv) != 3) {
        die('Wrong number of arguments for salsa20_8.');
    }
    $b = hex2bin($argv[2]);
    if (strlen($b) !== 64) {
        die('Input is of incorrect length.');
    }
    $result = Yescrypt::salsa20_core_binary($b, 8);
    echo $result;
    break;
case "benchmark":
    if (count($argv) < 4) {
        die('Bad arguments to benchmark.');
    }
    $iteration_count = (int)$argv[2];
    switch ($argv[3]) {
    case 'yescrypt':
        benchmarkYescrypt(
            $iteration_count,
            (int)$argv[4],      // N
            (int)$argv[5],      // r
            (int)$argv[6],      // p
            (int)$argv[7],      // t
            (int)$argv[8],      // g
            (int)$argv[9],      // flags
            (int)$argv[10]      // dkLen
        );
        break;
    case 'pwxform':
        benchmarkPwxform($iteration_count);
        break;
    case 'salsa20_8':
        benchmarkSalsa20_8($iteration_count);
        break;
    }
    break;
default:
    die('bad function');
}

function benchmarkYescrypt($iteration_count, $N, $r, $p, $t, $g, $flags, $dkLen)
{
    $start = microtime(true);
    for ($i = 0; $i < $iteration_count; $i++) {
        Yescrypt::calculate("password", "salt", $N, $r, $p, $t, $g, $flags, $dkLen);
    }
    $totalTime = microtime(true) - $start;
    if ($totalTime < 1.0) {
        echo "Iteration count is too small to be accurate.";
    } else {
        $c_s = $iteration_count / $totalTime;
        echo "$c_s c/s";
    }
}

function benchmarkPwxform($iteration_count)
{
    // XXX: do this better
    $pwxblock = str_repeat("\x00", YESCRYPT_PWXBYTES);
    $sbox = new Sbox(str_repeat("\x00", YESCRYPT_SBYTES));

    $start = microtime(true);
    for ($i = 0; $i < $iteration_count; $i++) {
        Yescrypt::pwxform($pwxblock, $sbox);
    }
    $totalTime = microtime(true) - $start;
    if ($totalTime < 1.0) {
        echo "Iteration count is too small to be accurate.";
    } else {
        $c_s = $iteration_count / $totalTime;
        echo "$c_s c/s";
    }
}

function benchmarkSalsa20_8($iteration_count)
{
    // XXX: do this better.
    $cell = str_repeat("\x00", 64);
    $start = microtime(true);
    for ($i = 0; $i < $iteration_count; $i++) {
        $cell = Yescrypt::salsa20_core_binary($cell, 8);
    }
    $totalTime = microtime(true) - $start;
    if ($totalTime < 1.0) {
        echo "Iteration count is too small to be accurate.";
    } else {
        $c_s = $iteration_count / $totalTime;
        echo "$c_s c/s";
    }
}
