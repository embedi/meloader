from construct import *

from .manifest import *
from .lut import MeLookupTable


def _calc_lut_offset(ctx):
    return ctx._.offset + ((ctx.manifest.manifest_size * 4 + 0x3F) & ~0x3F)


MeCodePartition = Struct(
    'partition',
    MeManifest,
    Optional(Pointer(_calc_lut_offset, MeLookupTable))
)


MeBlobPartition = Struct(
    'partition',
    Bytes('blob', lambda ctx: ctx._.size),
)


MePartition = Struct(
    'partition',
    Embedded(Switch(None, lambda ctx: ctx._.type, {
        0: MeCodePartition,
    }, default=MeBlobPartition))
)


__all__ = ['MeCodePartition', 'MePartition']