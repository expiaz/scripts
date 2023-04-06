#!/usr/bin/python3

from datetime import datetime
import argparse
from math import ulp

special = '@!#?$%'

parser = argparse.ArgumentParser(description='Generate basic wordlist')
parser.add_argument('-n', dest='n', help='append number (default 1..123). Format min-max or min (stops to 123)')
parser.add_argument('-y', dest='y', help='append years (default 1990-current). Format min (stop to current). Use -n 2005-2010 for arbitrary years')
parser.add_argument('-j', dest='j', default='', help='use these chars to join word and suffix')
parser.add_argument('-a', dest='a', default='', help='append these chars at the end')
parser.add_argument('-p', nargs='+', action='append', dest='p', required=True, help='base words for wordlist generation. Format <word[,word]>[]:<suffix[,suffix]>]')

args = parser.parse_args()

if args.n:
    [s, *e] = args.n.split('-')
    ns = int(s)
    ne = (int(e[0]) if e else 123) + 1
else:
    ns = ne = 0

ys = int(args.y) if args.y else 0
ye = datetime.now().year + 1 if args.y else 0

joints = list(args.j)
appends = list(args.a)

for p in args.p:
    [words, *sfx] = p[0].split(':')
    suffixes = sfx[0].split(',') if sfx else ''
    for w in words.split(','):
        wl = []
        wl.append(w)

        for a in appends:
            wl.append(w + a)
    
        for i in range(ns, ne):
            n = str(i)
            wl.append(w + n)
            for j in joints:
                wl.append(w + j + n)
            for a in appends:
                wl.append(w + n + a)
        
        for i in range(ys, ye):
            y = str(i)
            wl.append(w + y)
            for j in joints:
                wl.append(w + j + y)
            for a in appends:
                wl.append(w + y + a)
        
        for s in suffixes:
            wl.append(w + s)
            for j in joints:
                wl.append(w + j + s)
            for a in appends:
                wl.append(w + s + a)

        for i in wl:
            print(i)
        for u in wl:
            print(u[0].upper() + u[1:])


# '-j' '@!#'
# '-a' '@!#'
# '-y' '1990'
# '-n' '36-56'
# '-p' 'base,base2:a,b,c,d'