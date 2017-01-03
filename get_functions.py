#!/usr/bin/env python2
import sys
from pwn import log
from pycparser import parse_file
import pycparser
import json
import os.path


FAKE_LIBC = "c_code/utils/fake_libc_include"


class information:
    def __init__(self):
        self.isptr = False
        self.name = ""
        self.type = ""
        self.isfunct = False
        self.params = []


def get_type(x):
    f = information()
    while(not isinstance(x, pycparser.c_ast.IdentifierType)):
        if(isinstance(x, pycparser.c_ast.PtrDecl)):
            f.isptr = True
        x = x.type
    f.type = " ".join(x.names)
    return f


def print_function(f):
    tolog = []
    for p in f.params:
        con = " "
        if(p.isptr):
            con = "* "
        if(p.name):
            tolog.append(p.type + con + p.name)
    params = ", ".join(tolog)
    con = " "
    if(f.isptr):
        con = "* "
    log.info(f.type + con + f.name + "(" + params + ")")


def export_function(f):
    fdesc = {}
    fdesc["name"] = f.name
    fdesc["parameters"] = []
    fdesc["monitor"] = True
    for p in f.params:
        entry = {}
        entry["name"] = p.name
        if(p.isptr):
            entry["type"] = "addr"
            if("char" in p.type):
                entry["type"] = "string"
        else:
            entry["type"] = "num"
        entry["monitor"] = False
        if(p.name):
            fdesc["parameters"].append(entry)
    filename = "functions/" + f.name + ".json"
    if(os.path.isfile(filename)):
        log.warn("File " + filename + " already exists!")
    else:
        with open(filename, 'w') as outfile:
            json.dump(fdesc, outfile,
                      sort_keys=True, indent=4, separators=(',', ': '))


def get_functions(tree):
    functions = []
    for e in tree:
        if isinstance(e.type, pycparser.c_ast.FuncDecl):
            f = get_type(e)
            f.isfunct = True
            f.name = e.name
            for ee in e.type.args.params:
                p = get_type(ee)
                p.name = ee.name
                f.params.append(p)
            functions.append(f)
    return functions


def main(filename):
    ast = parse_file(filename, use_cpp=True, cpp_args="-I" + FAKE_LIBC)
    functions = get_functions(ast.ext)
    for f in functions:
        # print_function(f)
        export_function(f)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        try:
            log.error("Usage: %s <path_to_file>" % __file__)
        except:
            sys.exit(-1)
    main(sys.argv[1])
