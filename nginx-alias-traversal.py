import sys
import git
import os
import re
from subprocess import check_output, CalledProcessError

# @see @see https://github.com/hakaioffsec/navgix
# @see https://labs.hakaioffsec.com/nginx-alias-traversal/
# @see https://github.com/bayotop/off-by-slash

gitrep = sys.argv[1]
tag = None
if len(sys.argv) > 2:
    tag = sys.argv[2]

repo = git.Repo(gitrep)
tags = reversed(list(map(lambda e: e.name, repo.tags)))

candidates = []

def success(s):
    return f"\033[;32m{s}\033[0m"

def warning(s):
    return f"\033[;33m{s}\033[0m"

def error(s):
    return f"\033[;31m{s}\033[0m"

if tag != None and tag not in tags:
    print(error("Tag %s not found" % tag))
    sys.exit(1)

loc_reg = "location[^\/]+\/[_.a-zA-Z0-9+*$-\/]*[^\/]\s+\{"

for tag in tags:
    repo.git.checkout(tag)
    print(tag)
    try:
        matches = check_output(["grep", "-lRP", loc_reg, gitrep])
    except CalledProcessError:
        matches = b''
    for match_file in matches.splitlines():
        print(match_file.decode('utf-8'))

        try:
            locations = check_output(["grep", "-nRP", loc_reg, match_file])
        except CalledProcessError:
            locations = b''

        try:
            aliases = check_output(["grep", "-nRP", "alias \/[_.a-zA-Z0-9-\/]*\/;", match_file])
        except CalledProcessError:
            aliases = b''

        f = open(match_file)
        lv = 0
        lines = f.readlines()
        f.close()

        for m in locations.splitlines():
            location_start = int(m.decode('utf-8').split(':')[0])
            #print("Start of location at %d: %s" % (location_start, lines[location_start-1]))
            i = location_start
            lv = lines[i-1].count('{')
            # end of location block
            location_end = 0
            while lv > 0 and i < len(lines):
                l = lines[i].rstrip()
                for y in range(len(l)):
                    c = l[y]
                    if c == '{':
                        lv = lv+1
                    elif c == '}':
                        if lv == 0:
                            print(error("Dangling } at line %d position %d" % (i,y)))
                            break
                        lv = lv-1
                        if lv == 0:
                            location_end = i + 1
                            #print("End of location at %d: %s" % (location_end, lines[location_end-1]))
                i = i+1

            for a in aliases.splitlines():
                alias_line = int(a.decode('utf-8').split(':')[0])
                if alias_line > location_start and alias_line < location_end:
                    # vulnerable alias in contained in location block
                    candidates.append(tag)
                    print(success("%d:%s%d:%s" % (location_start, lines[location_start-1], alias_line, lines[alias_line-1])))

print()
print('Tag matched:')
for tag in candidates:
    print("\t%s" % tag)
