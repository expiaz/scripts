import sys
import git
import os
import json

"""
Parse symfony Exception HTML page to JSON in JS:
JSON.stringify([...document.querySelectorAll('.trace-line.trace-from-vendor')].map(e => ({
  code: e.querySelector('ol>li.selected code').textContent.trim(),
  line: parseInt(e.querySelector('ol').getAttribute('start')) + [...e.querySelector('ol').children].indexOf(e.querySelector('ol>li.selected')),
  file: e.querySelector('.trace-file-path a').textContent.trim()
})))

Then search through the tags the find a version matching the occurences of code at lines given in the exception
"""

errjson = sys.argv[1]
gitrep = sys.argv[2]
coderoot = sys.argv[3]
classroot = sys.argv[4]

repo = git.Repo(gitrep)
t = list(map(lambda e: e.name, repo.tags))
tags = reversed(t)
print("Found %d tags for %s" % (len(t), gitrep))

candidates = {}

def success(s):
    return f"\033[;32m{s}\033[0m"

def warning(s):
    return f"\033[;33m{s}\033[0m"

def error(s):
    return f"\033[;31m{s}\033[0m"

f = open(errjson)
c = json.loads(f.read())
f.close()
checks = []

for check in c:
    if check['file'].startswith(classroot):
        checks.append(check)

for tag in tags:
    repo.git.checkout(tag)
    print(tag)
    matches = []
    
    for check in checks:
        # filename = check['class'].replace('\\','/') + '.php'
        # filepath = coderoot + os.sep + filename
        filepath = coderoot + check['file'].replace(classroot, '')
        line = check['line']
        needle = check['code']
        if os.path.isfile(filepath):
            print(success(filepath))
            with open(filepath) as phpfile:
                code = phpfile.readlines()
                if len(code) < line:
                    print(error('\tno line %d' % line))
                else:
                    #print(len(code), line)
                    source = code[line-1].rstrip()
                    found = False
                    #print(source)
                    if source.find(needle) != -1:
                        print(success('\t%s line %d' % (needle, line)))
                        found = True
                    else:
                        # check the line before

                        # check the line after
                        
                        print(error('\tno %s line %d' % (needle, line)))

                    matches.append({
                        'line': line,
                        'match': needle,
                        'file': filepath,
                        'success': found
                    })
            
        else:
            print(error(filepath))

    candidates[tag] = matches


def count_success(matches):
    suc = 0
    for m in matches:
        if m['success']:
            suc = suc +1
    return suc

print("")
print("CANDIDATES")
for k in sorted(candidates, key=lambda e: count_success(candidates[e])):
    if len(candidates[k]) > 0:
        print("%d/%d %s" % (
            count_success(candidates[k]),
            len(checks),
            k
        ))
        # for m in candidates[k]:
        #     if m['success']:
        #         f = success
        #         fmt = '+'
        #     else:
        #         f = error
        #         fmt = '-'
        #     print(f("[%s] %s:%d %s" % (
        #         fmt,
        #         m['file'],
        #         m['line'],
        #         m['match']
        #     )))