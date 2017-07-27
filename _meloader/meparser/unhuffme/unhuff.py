# /*
#  * Unhuffme by bla<blapost@gmail.com>
#  *
#  * Indispensable help by:
#  *   Igor Skochinsky, phcoder, Corey Kallenberg, Xeno Kovah, Rafal Wojtczuk
#  *
#  * Copyright (C) 2015-2015 bla <blapost@gmail.com>
#  * All rights reserved.
#  */

from .dict_cpt_code import dict_cpt_code
from .dict_cpt_data import dict_cpt_data
from .dict_pch_code import dict_pch_code
from .dict_pch_data import dict_pch_data


SHAPE_PCH = (
    0, 0xec000000, 0x9b000000, 0x5f000000, 0x3bc00000,
    0x27400000, 0x12b00000, 0x02700000, 0x01600000,
    0x00aa0000, 0x001f0000, 0x00050000, 0x00018000, 0
)

SHAPE_CPT = (
    0, 0xfc000000, 0xaa000000, 0x6d800000, 0x4a000000,
    0x31200000, 0x19f00000, 0x07800000, 0x00780000, 0
)


M32 = 0xffffffffL


def m32(n):
    return n & M32


def madd(a, b):
    return m32(a+b)


def msub(a, b):
    return m32(a-b)


def mls(a, b):
    return m32(a << b)


def mrs(a, b):
    return m32(a >> b)


def _dictchunk(dict, r):
    start = r * 16 + 1
    end = start + ord(dict[r * 16])
    return dict[start:end]


def fashhuff(huff, outlen, dict, shape):
    pos, outpos = 0, 0
    idx, bitbuf = 0, 0
    out = b''

    for byte in huff[:4]:
        bitbuf = bitbuf << 8 | ord(byte)

    pos = 32
    while outpos < outlen:
        idx, symlen = 0, 7
        while bitbuf < shape[symlen - 6]:
            # idx += ((((shape[symlen - 7] - 1) &  - shape[symlen - 6]) & 0xFFFFFFFF >> (32 - symlen))) + 1
            idx = madd(idx, madd(mrs(msub(msub(shape[symlen - 7], 1), shape[symlen - 6]), msub(32, symlen)), 1))
            symlen += 1

        r = msub(shape[symlen - 7], 1)
        r = mrs(r, msub(32, symlen))
        r = msub(r, mrs(bitbuf, msub(32, symlen)))
        r = madd(r, idx)

        out += dict[r]
        outpos += len(dict[r])

        while symlen > 0:
            s = 8 - (pos & 7)
            t = ord(huff[pos >> 3])
            t = mls(t, msub(8, s))
            s = symlen if s > symlen else s
            t >>= 8 - s
            bitbuf = mls(bitbuf, s)
            bitbuf |= t
            symlen -= s
            pos += s

    return out


def unhuff(huff, outlen, flags, version):

    if version == 6:
        shape = SHAPE_PCH
        cfast = dict_pch_code
        dfast = dict_pch_data
    else:
        shape = SHAPE_CPT
        cfast = dict_cpt_code
        dfast = dict_cpt_data

    if flags == 'UNCOMPRESSED':
        return huff
    elif flags == 'CODE':
        return fashhuff(huff, outlen, cfast, shape)
    elif flags == 'DATA':
        return fashhuff(huff, outlen, dfast, shape)
