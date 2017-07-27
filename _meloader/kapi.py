KAPI_9_0_30_1482_NAMES = {
    0x018: 'Export',
    0x024: 'Export3?',
    0x030: 'Import',
    0x03C: 'Import2?',
    0x054: 'Export2?',
    0x0A8: 'FreeMem',
    0x0F0: 'AllocMem',
    0x21C: 'Queue2?',
    0x252: 'Queue',
    0x266: 'Timeout?',
    0x2D0: 'Mutex',
    0x348: 'Semaphore',
    0x354: 'Semaphore2?',
    0x3D8: 'Thread',
    0x5AC: 'Timer',
    0x5A0: 'Timer2',
}

KAPI_9_0_30_1482_DECLS = """
struct KAPI_EXPORT_TABLE {
    short unk1;
    short len;
    void* func[0];
};\n

struct KAPI_EXPORT_DESCR {
    int id;
    struct KAPI_EXPORT_TABLE* table;
    int unk1;
    int unk2;
};\n

struct KAPI_IMPORT_DESCR {
    int id;
    void* ptr;
};\n
"""

KAPI = {
    '9.0.30.1482': (None, 0x1000, KAPI_9_0_30_1482_NAMES, KAPI_9_0_30_1482_DECLS),
}
