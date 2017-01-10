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
            log.info("{} not found in {}".format(funcname, r))
            continue
        with open(funfile) as f:
            content = f.readlines()
        for l in content:
            info = json.loads(l)
            p_names = [x["name"] for x in info["parameters"]]
            if not p_names:
                continue

            for p in info["parameters"]:
                if p["name"] not in parameters:
                    parameters[p["name"]] = []
                parameters[p["name"]].append(p["content"])

        find_dub(parameters)
        all_params.append(parameters)
    find_dub_all(all_params)


def find_dub(params):
    for p in params:
        tocheck = []
        for x in params[p]:
            tocheck.append(x)
        if len(tocheck) != len(set(tocheck)):
            log.warn("Same {} found in same run!".format(p))


def find_dub_all(params):
    ps = [p for p in params]
    all_keys = []
    for p in ps:
        all_keys += p.keys()
    all_keys = list(set(all_keys))

    for key in all_keys:
        index = 0
        for param in params:
            tocheck = params[:index] + params[index+1:]
            listing = []
            for c in tocheck:
                if c.get(key):
                    listing.append(c[key])
            # If you think hard enough, this makes sense:
            listing = [i for j in listing for i in j]
            if params[index].get(key):
                for x in params[index][key]:
                    if x in listing:
                        log.warn("Same {} found in different runs".format(key))
            index = index + 1


if __name__ == '__main__':
    if len(sys.argv) != 3:
        try:
            log.error("Usage: %s <process name or PID> <function name>" %
                      __file__)
        except:
            sys.exit(-1)

    main(sys.argv[1], sys.argv[2])
