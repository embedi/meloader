from construct import *

from .version import MeVersion
from .module import *
from .misc import *


MeManifestEntry = Struct(
    'entry',
    Anchor('anchor'),
    String('tag', 4),
    CString('name'),
    Padding(lambda ctx: 16 - len(ctx.name) - 1),
    Bytes('hash', 32),
    ULInt32('base_addr'),
    ULInt32('offset'),
    ULInt32('size_uncompressed'),
    ULInt32('size_compressed'),
    ULInt32('memory_size'),
    ULInt32('pre_uma_size'),
    ULInt32('entry_point'),
    Anchor('flags_offset'),
    Peek(CBitwise(Bytes('flags_bits', 24))),
    Embedded(CBitStruct(
        'flags',
        Flag('load_state'),
        CBitField('power_type', 2),
        Flag('uma_dependency'),
        CBitField('compression_type', 3),
        CBitField('load_stage', 4),
        CBitField('api_type', 3),
        Flag('load'),
        Flag('initialize'),
        Flag('privileged'),
        CBitField('alias_pages1', 3),
        CBitField('alias_pages2', 2),
        Flag('pre_uma_load'),
        Flag('unknown_flag'),
    )),
    ULInt32('unknown54'),
    ULInt32('unknown58'),
    Bytes('unknown5C', 4),
    Padding(1),
    OnDemand(Switch('module', lambda ctx: ctx.compression_type, {
        1: MeHuffmanModule,
        2: MeLzmaModule,
    }, default=MePlainModule)),
)

MeManifestHeader = Struct(
    'header',
    ULInt16('module_type'),
    ULInt16('module_subtype'),
    ULInt32('header_length'),
    ULInt32('header_version'),
    Embedded(CBitStruct(
        'flags',
        Flag('signed'),
        Flag('production'),
        Padding(30),
    )),
    ULInt32('module_vendor'),
    ULInt32('date'),
    ULInt32('manifest_size'),
    String('tag', 4),
    ULInt32('num_modules'),
    MeVersion,
    Bytes('unknown2C', 76),
    ULInt32('pubkey_size'),
    ULInt32('scratch_size'),
    Bytes('pubkey_mod', 256),
    ULInt32('pubkey_exp'),
    Bytes('signature', 256),
    String('name', 12),
)

MeManifest = Struct(
    'manifest',
    Embedded(MeManifestHeader),
    Rename('entries', Array(lambda ctx: ctx.num_modules, MeManifestEntry)),
)


__all__ = ['MeManifestEntry', 'MeManifestHeader', 'MeManifest']
