from construct import *


MeVersion = Struct(
    'version',
    ULInt16('major'),
    ULInt16('minor'),
    ULInt16('hotfix'),
    ULInt16('build'),
)


__all__ = ['MeVersion']
