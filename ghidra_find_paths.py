# Finds paths between 2 symbols
#@author JaciBrunning
#@category Graph
#@see https://gist.github.com/JaciBrunning/53c62ffd1aecd525915532f9892f9273

from ghidra.program.model.symbol import RefType
import itertools
import hashlib

listing = currentProgram.getListing()
symbols = currentProgram.getSymbolTable()
addresses = currentProgram.getAddressFactory()

def group(iterator, n):
    while True:
        chunk = tuple(itertools.islice(iterator, n))
        if not chunk:
            return
        yield chunk

def getReferersOf(symbol):
    refs = symbol.getReferences()
    for ref in refs:
        # FUN_
        if listing.isInFunction(ref.getFromAddress()):
            yield (listing.getFunctionContaining(ref.getFromAddress()).getSymbol(), ref.getFromAddress())
        # PTR_
        elif symbols.hasSymbol(ref.getFromAddress()):
            for sym in symbols.getSymbols(ref.getFromAddress()):
                yield (sym, ref.getFromAddress())
        #else:
        #    print("UNCLASSIFIED REF: " + str(ref))

def find_paths(a, b):
    visited = [ (a,a.getAddress()) ]
    queue = [ [ (a,a.getAddress()) ] ]

    while queue:
        path = queue.pop(0)
        symbol, addr = path[-1]

        if symbol == b:
            yield path

        for el in getReferersOf(symbol):
            # Change path to visited to prevent loops globally, not just in the current path.
            # Can be useful when you only want the shortest path for each tree.
            if el not in path:
                visited.append(el)
                new_path = list(path)
                new_path.append(el)
                queue.append(new_path)

def print_paths(a, b):
    if a == None:
        print("Destination")
    for path in find_paths(a, b):
        print("Path({}):".format(len(path)))
        first = True
        for el in group(reversed(path), 10):
            s = " -> ".join([str(sym) + " (" + str(addr) + ")" for sym,addr in el])
            print("\t{}{}".format("-> " if not first else "", s))
            first = False

def ask_symbol(title, message):
    sym = None
    while sym is None:
        search = askString(title, message)
        syms = list(symbols.getSymbols(search))

        if len(syms) == 0:
            addr = addresses.getAddress(search)
            if addr != None:
                syms = list(symbols.getSymbols(addr))

        if len(syms):
            if len(syms) > 1:
                return ask_symbol("Multiple occurences found", "Enter symbol address instead")
            sym = syms[0]
    return sym

src_symbol = ask_symbol("Source Symbol/Address", "Source symbol name ?")
dst_symbol = ask_symbol("Destination Symbol/Address", "Destination symbol name ?")

print_paths(dst_symbol, src_symbol)
