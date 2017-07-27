from construct import *

from .fpt import MeFirmwarePartitionTable


MeRegion = Struct(
    'region',
    Embedded(Select(None, MeFirmwarePartitionTable,
                    Struct(None, Bytes('rombypass', 16), MeFirmwarePartitionTable)))
)


__all__ = ['MeRegion']