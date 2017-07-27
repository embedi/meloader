from idaapi import *
from idc import *
from idautils import *


def memcpy(dst, src, n):
    for i in range(0, n):
        PatchByte(dst + i, Byte(src + i))

