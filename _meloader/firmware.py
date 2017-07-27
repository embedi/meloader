from idaapi import *
from idc import *
from idautils import *

from .meparser import MeRegion
from .module import load_module
from .rapi import RAPI
from .misc import *


def load_firmware(blob, module_names):
    region = MeRegion.parse(blob)
    version = _version_as_str(region)

    if module_names:
        man_entry_filter = lambda x: x.name in module_names
    else:
        man_entry_filter = lambda x: True

    rapi = _add_rapi(version)

    modules = []
    for fpt_entry in filter(lambda x: x.partition and x.type == 0, region.fpt.entries):
        partition = fpt_entry.partition.value
        for man_entry in filter(man_entry_filter, partition.manifest.entries):
            blob = man_entry.module.value
            name = man_entry.name
            base = man_entry.base_addr
            memory_size = man_entry.memory_size
            print '%s: alias_pages1=%s, alias_pages2=%s' % (man_entry.name, man_entry.alias_pages1, man_entry.alias_pages2)
            has_kapi = man_entry.alias_pages1 or man_entry.alias_pages2
            # if name != 'HOSTCOMM':
            #     continue
            print 'Processing %s...' % name
            module = load_module(blob, name, version, base, memory_size, has_kapi)
            modules.append(module)

    imports, exports = {}, {}

    for module in modules:
        module.analyze()
        _rename_all(module)
        for id, addr in module.imports().items():
            imports[id] = imports.get(id, []) + [addr]
        for id, addr in module.exports().items():
            exports[id] = exports.get(id, []) + [addr]

    try:

        print 'IMPORTS'
        for id, addr_list in sorted(imports.items(), key=lambda x: x[0]):
            print '\t' + '%08X: %s' % (id, ' '.join('%08X' % addr for addr in addr_list))
        print 'EXPORTS'
        for id, addr_list in sorted(exports.items(), key=lambda x: x[0]):
            print '\t' + '%08X: %s' % (id, ' '.join('%08X' % addr for addr in addr_list))

        print '-' * 80

    except:
        pass

    # print 'EXPORTS'
    # for id, addr_list in sorted(exports.items(), key=lambda x: x[0]):
    #     print '\t' + '%08X: %s' % (id, ' '.join('%08X' % addr for addr in addr_list))

    for id, addr_list in exports.items():
        table_addr = addr_list[0]
        ptr_addr_list = imports.get(id, [])
        for ptr_addr in ptr_addr_list:
            PatchDword(ptr_addr, table_addr)
            MakeDword(ptr_addr)

    _analyze_rapi(rapi, version)


def _rename_all(module):
    for seg in filter(None, (module.kapi, module.code, module.data, module.bss)):
        for ea in range(seg.startEA, seg.endEA):
            if (has_dummy_name(GetFlags(ea)) or Name(ea).startswith('nullsub')) \
                    and not Name(ea).startswith('loc') \
                    and not Name(ea).startswith('a'):
                make_name(ea, '%08X' % ea)


def _version_as_str(region):
    if region.fpt.version.major != 0:
        version = region.fpt.version
    else:
        ftpr = filter(lambda ftp_entry: ftp_entry.type == 0, region.fpt.entries)[0].partition.value
        version = ftpr.manifest.version
    return '%d.%d.%d.%d' % (version.major, version.minor, version.hotfix, version.build)


def _add_rapi(version):
    base, size, _, _ = RAPI.get(version, (0x20000000, 0x1000, None, None))

    rapi = add_seg(base, size, 'RAPI')
    return rapi


def _analyze_rapi(rapi, version):
    _, _, names, _ = RAPI.get(version, (None, None, {}, None))

    for ea in range(rapi.startEA, rapi.endEA):
        if Name(ea):
            name = names.get(ea - rapi.startEA, '%08X' % ea)
            PatchDword(ea, 0x7EE0)  # j [blink] -> nop
            MakeFunction(ea)
            make_name(ea, name)
