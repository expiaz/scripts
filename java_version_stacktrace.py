import sys
import git
import os

errf = sys.argv[1]
gitrep = sys.argv[2]
javabase = sys.argv[3]

pkgfilter = None
if len(sys.argv) > 4:
    pkgfilter = sys.argv[4]

repo = git.Repo(gitrep)
tags = reversed(list(map(lambda e: e.name, repo.tags)))

checks = []
candidates = {}

def success(s):
    return f"\033[;32m{s}\033[0m"

def warning(s):
    return f"\033[;33m{s}\033[0m"

def error(s):
    return f"\033[;31m{s}\033[0m"

with open(errf) as errfile:
    for l in errfile.readlines():
        err = l.rstrip()
        if pkgfilter is not None:
            if not err.startswith(pkgfilter):
                continue

        parts = err.split('.')
        # doSmth(File, java:31)
        funcname = parts[-2].split('(')[0]
        filename = parts[-2].split('(')[1]
        line = int(parts[-1].split(':')[1][:-1])
        pkg = parts[:-3]

        if parts[-3] != filename:
            print('Package %s differ from file %s, taking %s' % (pkg[-1], filename, filename))

        checks.append(
            (os.sep.join(pkg), filename, line, funcname)
        )

    for tag in tags:
        repo.git.checkout(tag)
        func = None
        matches = []
        print(tag)
        
        for check in checks:
            pkg, filename, line, funcname = check
            filepath = javabase + pkg + os.sep + filename + '.java'
            if os.path.isfile(filepath):
                print(success(filepath))
                # stacktrace are formatted as follows:
                # from exception to starting point
                # pkg.function(File:line)
                # the File:line part references the caller of this function
                # it means that we must check the the file contains a call to this function at this line
                # ex:
                # org.apache.cxf.transport.servlet.servicelist.FormattedServiceListWriter.getAbsoluteAddress(FormattedServiceListWriter.java:142)
                # org.apache.cxf.transport.servlet.servicelist.FormattedServiceListWriter.writeRESTfulEndpoint(FormattedServiceListWriter.java:171)
                # the file FormattedServiceListWriter.java as a call to getAbsoluteAddress on line 142
                # and the file FormattedServiceListWriter.java has a call to writeRESTfulEndpoint line 171
                if func is not None:
                    with open(filepath) as javaclass:
                        code = javaclass.readlines()
                        if len(code) < line:
                            print(error('\tno line %d' % line))
                        else:
                            #print(len(code), line)
                            source = code[line-1].rstrip()
                            #print(source)
                            if source.find(f"{func}(") != -1: #.func(
                                print(success('\t%s line %d' % (func, line)))
                                matches.append(check)
                            else:
                                # check the line before

                                # check the line after
                                
                                print(error('\tno %s line %d' % (func, line)))
                
            else:
                print(error(filepath))
            
            func = funcname

        candidates[tag] = matches

print("")
print("CANDIDATES")
for k in sorted(candidates, key=lambda e: len(candidates[e])):
    if len(candidates[k]) > 0:
        print("%d/%d %s" % (
            len(candidates[k]),
            len(checks),
            k
        ))