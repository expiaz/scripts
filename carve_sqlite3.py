import sys,re,struct

CHUNK_SZ = 4096

'''
@see https://www.sqlite.org/fileformat.html

0	16	The header string: "SQLite format 3\000"
16	2	The database page size in bytes. Must be a power of two between 512 and 32768 inclusive, or the value 1 representing a page size of 65536.
18	1	File format write version. 1 for legacy; 2 for WAL.
19	1	File format read version. 1 for legacy; 2 for WAL.
20	1	Bytes of unused "reserved" space at the end of each page. Usually 0.
21	1	Maximum embedded payload fraction. Must be 64.
22	1	Minimum embedded payload fraction. Must be 32.
23	1	Leaf payload fraction. Must be 32.
24	4	File change counter.
28	4	Size of the database file in pages. The "in-header database size".
32	4	Page number of the first freelist trunk page.
36	4	Total number of freelist pages.
40	4	The schema cookie.
44	4	The schema format number. Supported schema formats are 1, 2, 3, and 4.
48	4	Default page cache size.
52	4	The page number of the largest root b-tree page when in auto-vacuum or incremental-vacuum modes, or zero otherwise.
56	4	The database text encoding. A value of 1 means UTF-8. A value of 2 means UTF-16le. A value of 3 means UTF-16be.
60	4	The "user version" as read and set by the user_version pragma.
64	4	True (non-zero) for incremental-vacuum mode. False (zero) otherwise.
68	4	The "Application ID" set by PRAGMA application_id.
72	20	Reserved for expansion. Must be zero.
92	4	The version-valid-for number.
96	4	SQLITE_VERSION_NUMBER
'''
SQLITE3_HDR_LEN = 100



with open(sys.argv[1], 'rb') as f:
    # TODO parse chunks 4096 or so bytes and handle splited header
    mem = f.read()
    sqlite3_magic = b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00"
    for m in re.finditer(sqlite3_magic, mem):
        start, end = m.span()
        print()
        print(sqlite3_magic)
        print(start, end)
        hdr = mem[start:start+SQLITE3_HDR_LEN]

        if len(hdr) < SQLITE3_HDR_LEN:
            # TODO next file
            print("%s has an uncomplete header missing %d bytes" % (sys.argv[1], SQLITE3_HDR_LEN-len(hdr)))
            sys.exit(1)
        # 16
        ptr = end
        page_size = struct.unpack('>H', mem[ptr:ptr+2])[0]
        ptr += 2
        if page_size == 1:
            print('page_size is 0x00 0x01 => 65536')
            page_size = 65536
        else:
            print('page_size:\t%d' % page_size)
        # 18
        file_format_write_version = mem[ptr]
        ptr += 1
        print('file_format_write_version:\t%d (%s journaling mode)' % (
            file_format_write_version,
            'rollback' if file_format_write_version == 1 else 'WAL'
        ))
        # 19
        file_format_read_version = mem[ptr]
        ptr += 1
        print('file_format_read_version:\t%d (%s journaling mode)' % (
            file_format_read_version,
            'rollback' if file_format_read_version == 1 else 'WAL'
        ))
        # 20
        reserved_bytes_per_page = mem[ptr]
        ptr += 1
        print('reserved_bytes_per_page:\t%d' % reserved_bytes_per_page)
        # 21
        max_payload_fractions = mem[ptr]
        ptr += 1
        if max_payload_fractions != 64:
            print("[ERROR] max_payload_fractions is %d" % max_payload_fractions)
            continue
        # 22
        min_payload_fractions = mem[ptr]
        ptr += 1
        if min_payload_fractions != 32:
            print("[ERROR] min_payload_fractions is %d" % min_payload_fractions)
            continue
        # 23
        leaf_payload_fractions = mem[ptr]
        ptr += 1
        if leaf_payload_fractions != 32:
            print("[ERROR] leaf_payload_fractions is %d" % leaf_payload_fractions)
            continue
        # 24
        file_change_counter = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("file_change_counter:\t%d" % file_change_counter)
        # 28
        '''
        The in-header database size is only considered to be valid if it is non-zero and if the 4-byte change counter at offset 24 exactly matches the 4-byte version-valid-for number at offset 92.
        The in-header database size is always valid when the database is only modified using recent versions of SQLite, versions 3.7.0 (2010-07-21) and later. If a legacy version of SQLite writes to the database, it will not know to update the in-header database size and so the in-header database size could be incorrect. But legacy versions of SQLite will also leave the version-valid-for number at offset 92 unchanged so it will not match the change-counter. Hence, invalid in-header database sizes can be detected (and ignored) by observing when the change-counter does not match the version-valid-for number.
        '''
        in_hdr_db_size = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("in_hdr_db_size:\t%d" % in_hdr_db_size)
        # 32
        free_page_list = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("free_page_list:\t%d" % free_page_list)
        # 36
        total_freelist_pages = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("total_freelist_pages:\t%d" % total_freelist_pages)
        # 40
        schema_cookie = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("schema_cookie:\t%d" % schema_cookie)
        # 44
        schema_format_number = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("schema_format_number:\t%d" % schema_format_number)
        # TODO if not 1,2,3,4 then not a DB file
        # 48
        suggested_cache_size = struct.unpack('>i', mem[ptr:ptr+4])[0]
        ptr+=4
        print("suggested_cache_size:\t%d" % suggested_cache_size)
        # 52
        auto_vacuum_setting = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("auto_vacuum_setting:\t%d" % auto_vacuum_setting)
        # 56
        text_encoding = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        if text_encoding not in [1,2,3]:
            print("[ERROR] text encoding not in defined constants: %d" % text_encoding)
            continue
        else:
            print("text_encoding:\t%d" % text_encoding)
        # 60
        user_version_number = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("user_version_number:\t%d" % user_version_number)
        # 64
        incremental_vacuum_setting = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        if auto_vacuum_setting == 0 and incremental_vacuum_setting != 0:
            print("[ERROR] incremental_vacuum_setting is %d when auto_vacuum_setting == 0" % incremental_vacuum_setting)
            continue
        else:
            print("incremental_vacuum_setting:\t%d" % incremental_vacuum_setting)
        # 68
        app_id = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("app_id:\t%d" % app_id)
        # 72
        reversed_zeros = mem[ptr:ptr+20]
        ptr+=20
        if reversed_zeros != (b"\x00"*20):
            print("[ERROR] reversed_zeros have values")
            continue
        # 92
        version_valid_for_number = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("version_valid_for_number:\t%d" % version_valid_for_number)
        # 96
        sqlite_version = struct.unpack('>I', mem[ptr:ptr+4])[0]
        ptr+=4
        print("SQLite version:\t%d" % sqlite_version)

        if in_hdr_db_size != 0 and file_change_counter == version_valid_for_number:
            db_size = in_hdr_db_size * page_size
            print('[VALID] in_hdr_db_size seems valid, db size is %d' % db_size)

            db_data = mem[start:start+db_size]
            if len(db_data) < db_size:
                print("%s has uncomplete data missing %d bytes starting from %d" % (sys.argv[1], db_size-len(db_data), start))
                sys.exit(1)

            db_name = '%s.sqlite3' % start
            with open(db_name, 'wb') as dbfile:
                dbfile.write(db_data)
            print('%s written to disk' % db_name)

        else:
            print('[ERROR] in_hdr_db_size is invalid, can\'t guess db size')
            continue
