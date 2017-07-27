import fnmatch

from idaapi import *
from idc import *
from idautils import *

from _meloader import *


def accept_file(li, n):

    # we support only one format per file
    if n > 0:
        return 0

    chunk = li.read(0x20)

    set_processor_type('arcmpct', SETPROC_ALL)

    return 'Intel ME firmware' if '$FPT' in chunk else None


def load_file(li, neflags, format):
    li.seek(0)
    blob = li.read(li.size())

    # module_names_list = AskStr('NET_STACK', 'Enter comma-seperated module names list (wildcards are fine too):')
    # module_names = module_names_list.split(',')

    load_firmware(blob, ())

    return 1