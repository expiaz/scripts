import sys,json

tg = set()
tu = set()

with open(sys.argv[1]) as f:
    groups = json.loads(f.read())
    i = 0
    diff = 1
    while diff != 0:
        diff = 0
        for g in groups:
            dn = g['attributes']['distinguishedName'][0]
            sam = g['attributes']['sAMAccountName'][0]
            if dn not in tg:
                if 'description' in g['attributes'] and "builtin administrators group" in g['attributes']['description'][0]:
                    tg.add(dn)
                    #print("%s" % (dn.split(',')[0][3:]))
                    diff = diff + 1
                elif 'memberOf' in g['attributes']:
                    for gp in g['attributes']['memberOf']:
                        if gp in tg:
                            #print("%s -> %s" % (gp, sam))
                            tg.add(dn)
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
                if gp in tg:
                    print("%s -> %s" % (gp, sam))
                    tu.add(dn)
