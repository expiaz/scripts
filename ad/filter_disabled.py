import sys,json

# python3 ntds_filter_disabled.py domain_users.json domain.ntds

# @see https://github.com/p0dalirius/msFlagsDecoder/blob/main/msFlagsDecoder.py#L15C39-L15C73
ACCOUNT_DISABLE_UAC_FLAG = 0b00000000000000000000000000000010

disabled = set()

with open(sys.argv[1]) as f:
    users = json.loads(f.read())
    for u in users:
        sam = u['attributes']['sAMAccountName'][0]
        sid = u['attributes']['objectSid'][0].split('-')[-1]
        if 'userAccountControl' in u['attributes'] and u['attributes']['userAccountControl'][0] & ACCOUNT_DISABLE_UAC_FLAG != 0:
            disabled.add(int(sid))
        elif 'msExchUserAccountControl' in u['attributes'] and u['attributes']['msExchUserAccountControl'][0] & ACCOUNT_DISABLE_UAC_FLAG != 0:
            disabled.add(int(sid))

with open(sys.argv[2]) as f:
    for l in f.readlines():
        parts = l.split(':')
        sam = parts[0]
        sid = int(parts[1])
        if sid not in disabled:
            print(l.strip())