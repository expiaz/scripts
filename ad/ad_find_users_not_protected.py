import sys,json

# python3 not_protected.py domain_groups.json domain_users.json 'CN=Protected Users,CN=Users,DC=domain,DC=com'

pg = 'CN=Protected Users,CN=Users,DC=domain,DC=com'
pg = sys.argv[3]

# @see https://github.com/p0dalirius/msFlagsDecoder/blob/main/msFlagsDecoder.py#L34C39-L34C73
NOT_DELEGATED_UAC_FLAG = 0b00000000000100000000000000000000

protected = set([pg])
pu = set()

with open(sys.argv[1]) as f:
    groups = json.loads(f.read())
    i = 0
    diff = 1
    while diff != 0:
        diff = 0
        for g in groups:
            dn = g['attributes']['distinguishedName'][0]
            if dn not in protected:
                if 'memberOf' in g['attributes']:
                    for gp in g['attributes']['memberOf']:
                        if gp in protected:
                            print("%10s -> %10s" % (gp.split(',')[0][3:], dn.split(',')[0][3:]))
                            protected.add(dn)
                            diff = diff + 1
        i = i +1

    print(i)

    # for g in groups:
    #     dn = g['attributes']['distinguishedName'][0]
    #     if dn in protected:
    #         if 'member' in g['attributes']:
    #             for mm in g['attributes']['member']:
    #                 pu.add(mm)
    #                 print("%10s -> %10s" % (dn.split(',')[0][3:], mm.split(',')[0][3:]))
    #                 protected.add(dn)


with open(sys.argv[2]) as f:
    users = json.loads(f.read())
    for u in users:
        dn = u['attributes']['distinguishedName'][0]
        sam = u['attributes']['sAMAccountName'][0]
        if 'memberOf' in u['attributes']:
            for gp in u['attributes']['memberOf']:
                if gp in protected:
                    print("%s -> %s" % (gp.split(',')[0][3:], sam))
                    pu.add(dn)
        if 'userAccountControl' in u['attributes'] and u['attributes']['userAccountControl'][0] & NOT_DELEGATED_UAC_FLAG != 0:
            print('UAC NOT_DELEGATED %s' % sam)
            pu.add(dn)
        elif 'msExchUserAccountControl' in u['attributes'] and u['attributes']['msExchUserAccountControl'][0] & NOT_DELEGATED_UAC_FLAG != 0:
            print('MSEXCH_UAC NOT_DELEGATED %s' % sam)
            pu.add(dn)