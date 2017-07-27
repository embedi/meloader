from construct import *


def CBitField(name, length):
    return BitField(name, length, swapped=True, bytesize=1)


def CBitStruct(name, *subcons):
    return CBitwise(Struct(name, *subcons))


def CBitwise(subcon):

    def resizer(length):
        if length & 7:
            raise SizeofError("size must be a multiple of 8", length)
        return length >> 3

    con = Buffered(subcon,
                   encoder=_encoder,
                   decoder=_decoder,
                   resizer=resizer
                   )

    return con


def _encoder(data):
    import binascii
    print binascii.hexlify(data)
    return data


def _decoder(data):
    bits = b''
    for byte in data:
        bits += b''.join(chr(bit) for bit in map(lambda n: (ord(byte) & (1 << n)) >> n, range(0, 8)))
    # print ''.join(('1' if ord(bit) else '0') for bit in bits)
    return bits


__all__ = ['CBitField', 'CBitStruct', 'CBitwise']
