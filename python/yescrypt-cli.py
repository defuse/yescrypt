#!/usr/bin/env python2

import sys
from array import *
from struct import *

import yescrypt

if len(sys.argv) < 2:
    print("Not enough arguments.")
    sys.exit(1)

if sys.argv[1] == "yescrypt":
    if len(sys.argv) != 11:
        print("Wrong number of arguments for yescrypt.")
        sys.exit(1)

    result = yescrypt.calculate(
        bytearray.fromhex(sys.argv[2]),
        bytearray.fromhex(sys.argv[3]),
        int(sys.argv[4]),
        int(sys.argv[5]),
        int(sys.argv[6]),
        int(sys.argv[7]),
        int(sys.argv[8]),
        int(sys.argv[9]),
        int(sys.argv[10])
    )

    sys.stdout.write(result)

elif sys.argv[1] == "pwxform":
    if len(sys.argv) != 4:
        print("Wrong number of arguments for pwxform.")
        sys.exit(1)

    # XXX: The use of 'I' here is probably not robust.
    pwxblock = bytearray.fromhex(sys.argv[2])
    pwxblock = unpack('I' * (len(pwxblock)//4), pwxblock)
    pwxblock = array('L', pwxblock)

    sbox = bytearray.fromhex(sys.argv[3])
    sbox = unpack('I' * (len(sbox)//4), sbox)
    sbox = array('L', sbox)
    sbox = yescrypt.Sbox(sbox)

    yescrypt.pwxform(pwxblock, sbox)

    for n in pwxblock:
        sys.stdout.write(pack('I', n))

elif sys.argv[1] == "salsa20_8":
    if len(sys.argv) != 3:
        print("Wrong number of arguments for salsa20_8")
        sys.exit(1)

    cell = bytearray.fromhex(sys.argv[2])
    cell = unpack('I' * (len(cell)//4), cell)
    cell = array('L', cell)

    yescrypt.salsa20(cell, 8)

    for n in cell:
        sys.stdout.write(pack('I', n))
