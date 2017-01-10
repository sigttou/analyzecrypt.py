#!/usr/bin/env python2
import sys
import json
from os import listdir, path
from pwn import log

PATH = "results/"


def main(target, funcname):
    global PATH
    PATH += target + '/'
    runs = [PATH + x + '/' for x in listdir(PATH) if path.isdir(PATH + x)]
    runnr = len(runs)
    log.info("Analyzing {} all {} runs of {}".format(funcname, runnr, target))
    all_params = []

    for r in runs:
        parameters = {}
        funfile = r + funcname + '.dat'
        if not path.isfile(funfile):
            log.warn("{} not found in {}".format(funcname, r))
            continue
        with open(funfile) as f:
            content = f.readline()
        info = json.loads(content)
        p_names = [x["name"] for x in info["parameters"]]
        if not p_names:
            log.warn("No parameters from {} in {}".format(funcname, r))
            continue
        log.info("Found '{}' as used parameters".format(", ".join(p_names)))

        for p in info["parameters"]:
            if p["name"] not in parameters:
                parameters[p["name"]] = []
            parameters[p["name"]].append(p["content"])

        log.info(parameters)
        all_params.append(parameters)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        try:
            log.error("Usage: %s <process name or PID> <function name>" %
                      __file__)
        except:
            sys.exit(-1)

    main(sys.argv[1], sys.argv[2])
