from construct import *

from .misc import *

MeLookupTableHeader = Struct(
    'header',
    Magic(b'LLUT'),
    ULInt32('chunk_count'),
    ULInt32('addr_base'),
    ULInt32('spi_base'),
    ULInt32('huff_len'),
    ULInt32('huff_start'),
    ULInt32('flags'),
    Array(5, ULInt32('unknown')),
    ULInt32('page_size'),
    ULInt32('version'),
    ULInt32('chipset'),
    ULInt32('revision'),
)


MeLookupTableEntry = Struct(
    'entry',
    Embedded(CBitStruct(
        None,
        CBitField('addr', 25),
        Enum(CBitField('flags', 7),
             UNCOMPRESSED=0x00,
             CODE=0x20,
             EMPTY=0x40,
             DATA=0x60)
    ))
)


MeLookupTable = Struct(
    'lut',
    Anchor('anchor'),
    Embedded(MeLookupTableHeader),
    Rename('entries', Array(lambda ctx: ctx.chunk_count, MeLookupTableEntry)),
)


__all__ = ['MeLookupTable', 'MeLookupTableEntry', 'MeLookupTableHeader']
