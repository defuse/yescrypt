<?php

require_once('scrypt.php');

$input = "   
    7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26
    ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d
    ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32
    76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e";

$output = "
   a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
   04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
   b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
   e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81";

$input = str_replace([" ", "\n", "\r"], '', $input);
$output = str_replace([" ", "\n", "\r"], '', $output);

$input_binary = pack("H*",$input);
$output_binary = Scrypt::salsa20_8_core_binary($input_binary);
echo bin2hex($output_binary) . "\n";
echo "$output\n";

$scrypt = Scrypt::calculate("", "", 4, 1, 1, 64);
echo bin2hex($scrypt) . "\n";

die();

$b0 = "
f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
           77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
           89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
           09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
";

$b1 = "
89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
           cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
           67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
           7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
";

$b0 = hex2bin(str_replace([" ", "\n", "\r"], '', $b0));
$b1 = hex2bin(str_replace([" ", "\n", "\r"], '', $b1));

$out = Scrypt::scryptBlockMix(1, [$b0, $b1]);
echo bin2hex($out[0]) . "\n";
echo bin2hex($out[1]) . "\n";

$b = "
f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
       77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
       89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
       09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
       89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
       cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
       67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
       7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
";
$b = hex2bin(str_replace([" ", "\n", "\r"], '', $b));
$b = str_split($b, 64);
$out = Scrypt::scryptROMix(1, $b, 16);
echo bin2hex(implode('', $out));
