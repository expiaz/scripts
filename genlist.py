#!/usr/bin/python3

from datetime import datetime
import argparse

special = '@*!#?$%%\'"'

parser = argparse.ArgumentParser(description="""
Generate basic wordlist
Example: -p entreprise,ville,departement:codepostal,123,23 -p covid:19,20 -y 2023 -n 1-10 -a all -j all -l 8
""")
parser.add_argument('-p', nargs='+', action='append', dest='p', required=True, help='base words for wordlist generation. Format <word[,word]>:<suffix[,suffix]>]')
parser.add_argument('-n', dest='n', help='append number (default 1..123). Format min-max or min to set only min')
parser.add_argument('-y', dest='y', help='append years (default 1990-current). Format min (stop to current). Use -n 2005-2010 for arbitrary years')
parser.add_argument('-j', dest='j', default='', help='use these chars to join word and suffix (all=%s)' % special)
parser.add_argument('-a', dest='a', default='', help='append these chars at the end (all=%s)' % special)
parser.add_argument('-l', dest='l', help='only keep results between min-max or at least min characters')

args = parser.parse_args()

if args.n:
    [s, *e] = args.n.split('-')
    ns = int(s)
    ne = (int(e[0]) if e else ns) + 1
else:
    ns = ne = 0

ys = int(args.y) if args.y else 0
ye = datetime.now().year + 1 if args.y else 0

if args.a == 'all':
    args.a = special
if args.j == 'all':
    args.j = special

joints = list(args.j)
appends = list(args.a)



if args.l:
    [s, *e] = args.l.split('-')
    minlen = int(s)
    maxlen = (int(e[0]) if e else 999)
else:
    minlen = 0
    maxlen = 999

def output_result(s):
    if minlen <= len(s) and maxlen >= len(s):
        print(s)

wl = set()

for p in args.p:
    [words, *sfx] = p[0].split(':')
    suffixes = sfx[0].split(',') if sfx else ''
    for w in words.split(','):
        wl.add(w)

        for a in appends:
            wl.add(w + a)
    
        for i in range(ns, ne):
            n = str(i)
            wl.add(w + n)
            for j in joints:
                wl.add(w + j + n)
            for a in appends:
                wl.add(w + n + a)
        
        for i in range(ys, ye):
            y = str(i)
            wl.add(w + y)
            for j in joints:
                wl.add(w + j + y)
            for a in appends:
                wl.add(w + y + a)
        
        for s in suffixes:
            wl.add(w + s)
            for j in joints:
                wl.add(w + j + s)
            for a in appends:
                wl.add(w + s + a)

for i in wl:
    output_result(i)
for u in wl:
    output_result(u[0].upper() + u[1:])


# '-j' '@!#'
# '-a' '@!#'
# '-y' '1990'
# '-n' '36-56'
# '-p' 'base,base2:a,b,c,d'