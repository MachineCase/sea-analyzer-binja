"""
NODE_SEA_BLOB extractor for Binary Ninja.
Supports Mach-O (__NODE_SEA_BLOB section) and PE (NODE_SEA_BLOB section).
"""

SEA_MAGIC = bytes([0x20, 0xDA, 0x43, 0x01])
JS_OFFSET = 0x31
FILENAME_OFFSET = 0x10


class SEAExtractionError(Exception):
    pass


class SEABlob:
    def __init__(self, magic, version, filename, js_code, raw_blob):
        self.magic = magic
        self.version = version
        self.filename = filename
        self.js_code = js_code
        self.raw_blob = raw_blob
        self.size = len(raw_blob)


def find_sea_section(bv):
    """
    Looks for NODE_SEA_BLOB in Mach-O or PE.
    Returns the section object or None.
    """
    section = bv.get_section_by_name("__NODE_SEA_BLOB")
    if section:
        return section

    section = bv.get_section_by_name("NODE_SEA_BLOB")
    if section:
        return section

    return None


def extract(bv):
    """
    Main extraction function.
    Returns a SEABlob object or raises SEAExtractionError.
    """
    section = find_sea_section(bv)
    if section is None:
        raise SEAExtractionError("No NODE_SEA_BLOB section found in this binary.")

    blob = bv.read(section.start, section.length)
    if not blob:
        raise SEAExtractionError("Failed to read NODE_SEA_BLOB section.")

    if blob[:4] != SEA_MAGIC:
        raise SEAExtractionError(
            f"Invalid magic number: {blob[:4].hex()} (expected {SEA_MAGIC.hex()})"
        )

    version = blob[4]

    filename_raw = blob[FILENAME_OFFSET:JS_OFFSET]
    filename = filename_raw.split(b"\x00")[0].decode("utf-8", errors="replace")

    js_bytes = blob[JS_OFFSET:]
    js_code = js_bytes.decode("utf-8", errors="replace")

    return SEABlob(
        magic=blob[:4].hex(),
        version=version,
        filename=filename,
        js_code=js_code,
        raw_blob=blob,
    )
