from construct import *

from .version import MeVersion
from .partition import MePartition
from .misc import *


class OwnerAdapter(Adapter):

    def _decode(self, obj, context):
        return obj if obj != b'\xFF\xFF\xFF\xFF' else None


class OffsetAdapter(Adapter):

    def _decode(self, obj, context):
        return obj if obj != 0xFFFFFFFF else None


MeFirmwarePartitionTableEntry = Struct(
    'entry',
    String('name', 4),
    OwnerAdapter(String('owner', 4)),
    OffsetAdapter(ULInt32('offset')),
    ULInt32('size'),
    ULInt32('tokens_on_start'),
    ULInt32('max_tokens'),
    ULInt32('scratch_sectors'),
    Embedded(CBitStruct(
        'flags',
        CBitField('type', 7),
        Flag('direct_access'),
        Flag('read'),
        Flag('write'),
        Flag('execute'),
        Flag('logical'),
        Flag('wop_disable'),
        Flag('excl_bloc_kuse'),
        Padding(2)
    )),
    Padding(2),
    If(lambda ctx: ctx.offset,
       OnDemand(Pointer(lambda ctx: ctx.offset, MePartition)))
)


MeFirmwarePartitionTableHeader = Struct(
    'fpt',
    Magic('$FPT'),
    ULInt32('num_entries'),
    ULInt8('bcd_version'),
    ULInt8('entry_type'),
    ULInt8('header_len'),
    ULInt8('check_sum'),
    ULInt16('flash_cycle_lifetime'),
    ULInt16('flash_cycle_limit'),
    ULInt32('uma_size'),
    Embedded(CBitStruct(
        'flags',
        Flag('effs_present'),
        CBitField('layout_type', 8),
        Padding(23),
    )),
    MeVersion
)


MeFirmwarePartitionTable = Struct(
    'fpt',
    Embedded(MeFirmwarePartitionTableHeader),
    Rename('entries', Array(lambda ctx: ctx.num_entries,
                            MeFirmwarePartitionTableEntry)),
)

__all__ = ['MeFirmwarePartitionTable', 'MeFirmwarePartitionTableHeader', 'MeFirmwarePartitionTableEntry']
