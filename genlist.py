#!/usr/bin/python3

from datetime import datetime
import itertools
import argparse
import re, sys

special = '@*!#?$%%\'"'

complexity_filters = {
    'any': r'.*',
    'lower': r'[a-z]',
    'upper': r'[A-Z]',
    'number': r'[0-9]',
    'special': r'[^a-zA-Z0-9]'
}

leet = {
    'a':'4',
    'b':'8',
    'e':'3',
    'g':'9',
    'i':'1',
    'l':'1',
    'o':'0',
    'r':'2',
    's':'5',
    't':'7',
    'y':'7',
    'z':'7'
}
leet_help = ','.join(['%s->%s'%(k,v) for (k,v) in leet.items()])


parser = argparse.ArgumentParser(description="""
Generate basic wordlist
Example: -p entreprise,ville,departement:codepostal,123,23 -p covid:19,20 -y 2023 -n 1-10 -a -j -l 8 -l33t ailo
""")
parser.add_argument('-p', nargs='+', action='append', dest='p', required=True, help='base words for wordlist generation. Format <word[,word]>:<suffix[,suffix]>]')
parser.add_argument('-n', nargs='*', action='append', dest='n', help='append number (default 1..123). Format min-max or min to set only min')
parser.add_argument('-y', dest='y', help='append years (default 1990-current). Format min (stop to current). Use -n 2005-2010 for arbitrary years')
parser.add_argument('-j', nargs='?', dest='j', default='', help='use these chars to join word and suffix (-j=%s)' % special)
parser.add_argument('-a', nargs='?', dest='a', default='', help='append these chars at the end (-a=%s)' % special)
parser.add_argument('-l', dest='l', help='only keep results between min-max or at least min characters')
parser.add_argument('-c', dest='c', default='any', help='Choose from %s. Only keep results that contains at least the specified characters set' % ','.join(complexity_filters.keys()))
parser.add_argument('-r', dest='r', help='only keep results that matches the given regex')
parser.add_argument('-l33t', nargs='?', dest='leet', default='', help='replace these chars for l33t mode (-l33t:%s)' % leet_help)


args = parser.parse_args()

complexity = args.c.split(',')
if 'all' in complexity:
    complexity = ['lower','upper','number','special']

if args.r:
    reg = re.compile(args.r)

numbers = []
if args.n:
    for nb in args.n:
        [s, *e] = nb[0].split('-')
        ns = int(s)
        ne = (int(e[0]) if e else ns) + 1
        numbers.append((ns, ne))

ys = int(args.y) if args.y else 0
ye = datetime.now().year + 1 if args.y else 0

if args.a == None:
    args.a = special
if args.j == None:
    args.j = special
if args.leet == None:
    args.leet = ''.join(leet.keys())
for c in args.leet:
    if c not in leet:
        print('leet char %s not in %s' % (c, ','.join(leet.keys())))
        sys.exit(1)

joints = list(args.j)
appends = list(args.a)

if args.l:
    [s, *e] = args.l.split('-')
    minlen = int(s)
    maxlen = (int(e[0]) if e else 999)
else:
    minlen = 0
    maxlen = 999



def filter_len(s):
    if minlen <= len(s) and maxlen >= len(s):
        filter_complexity(s)


def filter_complexity(s):
    for c in complexity:
        if c not in complexity_filters:
            print("Error: -c %s not found in %s" % (
                c,
                ','.join(complexity_filters.keys())
            ))
            sys.exit(0)
        if not re.search(complexity_filters[c], s):
            return
    filter_reg(s)


def filter_reg(s):
    if args.r != None:
        if re.fullmatch(reg, s):
            print(s)
    else:
        print(s)


wl = set()

for p in args.p:
    [words, *sfx] = p[0].split(':')
    suffixes = sfx[0].split(',') if sfx else ''
    for w in words.split(','):
        wl.add(w)

        for a in appends:
            wl.add(w + a)

        for (ns, ne) in numbers:
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

if args.leet:
    wleet = set()
    for i in wl:
        curr = i
        for c in args.leet:
            u = c.upper()
            l = c.lower()
            curr = curr.replace(u,leet[l]).replace(l,leet[l])
            wleet.add(i.replace(u,leet[l]).replace(l,leet[l]))
            wleet.add(curr)
    wl.update(wleet)

for i in wl:
    filter_len(i)
for u in wl:
    filter_len(u[0].upper() + u[1:])


# '-j' '@!#'
# '-a' '@!#'
# '-y' '1990'
# '-n' '36-56'
# '-p' 'base,base2:a,b,c,d'