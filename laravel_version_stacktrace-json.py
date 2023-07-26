import sys
import git
import os
import json

"""
Stack trace looks like this:
{
    "message": "",
    "exception": "Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException",
    "file": "/var/www/vendor/laravel/framework/src/Illuminate/Routing/AbstractRouteCollection.php",
    "line": 43,
    "trace": [
        {
            "file": "/var/www/vendor/laravel/framework/src/Illuminate/Routing/RouteCollection.php",
            "line": 162,
            "function": "handleMatchedRoute",
            "class": "Illuminate\\Routing\\AbstractRouteCollection",
            "type": "->"
        },
        {
            "file": "/var/www/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 673,
            "function": "match",
            "class": "Illuminate\\Routing\\RouteCollection",
            "type": "->"
        },
}

class is the name of the class called next
should be found in the previous error
e.g. /var/www/vendor/laravel/framework/src/Illuminate/Routing/Router.php:673 call Illuminate\\Routing\\RouteCollection->match()
then Illuminate/Routing/RouteCollection.php calls Illuminate\\Routing\\AbstractRouteCollection->handleMatchedRoute() at line 162
etc...

called like python3 laravel_version_stacktrace.py err.json /workspace/php/framework /workspace/php/framework/src/Illuminate /var/www/vendor/laravel/framework/src/Illuminate
"""

errjson = sys.argv[1]
gitrep = sys.argv[2]
coderoot = sys.argv[3]
classroot = sys.argv[4]

repo = git.Repo(gitrep)
t = list(map(lambda e: e.name, repo.tags))
tags = reversed(t)
print("Found %d tags for %s" % (len(t), gitrep))

checks = []
candidates = {}

def success(s):
    return f"\033[;32m{s}\033[0m"

def warning(s):
    return f"\033[;33m{s}\033[0m"

def error(s):
    return f"\033[;31m{s}\033[0m"

f = open(errjson)
stacktrace = json.loads(f.read())
f.close()

for trace in reversed(stacktrace['trace']):
    if trace['file'].startswith(classroot):
        check = {
            'line': int(trace['line']),
            'match': "%s(" % (trace['function']),
            'file': coderoot + trace['file'].replace(classroot, '')
        }
        checks.append(check)
        print(success("[+] add check for %s:%d %s" % (
            check['file'],
            check['line'],
            check['match'],
        )))

for tag in tags:
    repo.git.checkout(tag)
    print(tag)
    matches = []
    
    for check in checks:
        # filename = check['class'].replace('\\','/') + '.php'
        # filepath = coderoot + os.sep + filename
        filepath = check['file']
        line = check['line']
        needle = check['match']
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