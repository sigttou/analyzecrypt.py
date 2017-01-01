#!/usr/bin/env python2
import frida
import sys
from pwn import log
import json
import os

MODULES = []
FUNCTIONS = []

SCRIPT = """
    Interceptor.attach(ptr("{addr}"), {{
        onEnter: function(args) {{
            send({format});
        }}
    }});
"""


def on_message(message, data):
    if message['type'] == 'send':
        info = json.loads(str(message['payload']).encode('string-escape'),
                          strict=False)
        filename = "results/" + sys.argv[1] + "/" + info["name"] + ".dat"
        with open(filename, "a+") as f:
            json.dump(info, f)
            f.write("\n")
        log.info("stored call to " + info["name"])
    else:
        log.warning("Could not parse: " + str(message))


def genscript(info, funct):
    fstring = '\'{'
    fstring += '"name": "{}", '.format(funct.name)
    fstring += '"parameters": ['

    for p in info["parameters"]:
        if p["monitor"]:
            fstring += '{'
            fstring += '"name": "{}", '.format(p["name"])
            fstring += '"content": "\' + '
            if(p["type"] == "string"):
                fstring += '"\\' + '\\x" + '
                fstring += 'Memory.readCString('
                fstring += 'args[{}]'.format(info["parameters"].index(p))
                fstring += ').split("").map(function(a){return '
                fstring += 'a.charCodeAt(0).toString(16)}).join("\\'
                fstring += '\\x")'
            elif(p["type"] == "num"):
                fstring += 'args[{}]'.format(info["parameters"].index(p))
                fstring += '.toInt32()'
            elif(p["type"] == "addr"):
                fstring += 'args[{}]'.format(info["parameters"].index(p))
            else:
                log.warn("UNKNOWN TYPE IN: " + p)
            fstring += ' + \'"}, '

    if fstring[-2:] == ', ':  # remove ', '
        fstring = fstring[:-2]
    fstring += ']'
    fstring += '}\''
    d = {
            'addr': funct.absolute_address,
            'format': fstring
        }
    tosend = SCRIPT.format(**d)
    return tosend


def main(target):
    log.info("Going to analyze {}".format(target))
    try:
        session = frida.get_usb_device().attach(target)
    except frida.ServerNotRunningError:
        try:
            log.error("Please start frida server first")
        except:
            sys.exit(-1)
    except frida.TimedOutError:
        try:
            log.error("Frida timeout...")
        except:
            sys.exit(-1)

    with open("config/modules.json") as j:
        MODULES = json.load(j)
    log.info("Will look at: {}".format(', '.join(MODULES)))

    if not os.path.exists("results/" + sys.argv[1]):
        os.makedirs("results/" + sys.argv[1])

    # Get only needed Modules
    modules = session.enumerate_modules()
    tmp = []
    for M in MODULES:
        tmp.append(modules[[x.name for x in modules].index(M)])
    modules = tmp

    functions = []
    for x in modules:
        functions += x.enumerate_exports()
    log.info("Found {} functions".format(len(functions)))

    # Which functions do I need to look at?
    for filename in os.listdir("functions/"):
        with open("functions/" + filename) as j:
            FUNCTIONS.append(json.load(j))
    lookup = [x["name"] for x in FUNCTIONS]
    log.info("Will look for: {}".format(', '.join(lookup)))

    for f in lookup:
        result = functions[[x.name for x in functions].index(f)]
        log.info("Found {} in {} @ {}".format(result.name,
                                              result.module.name,
                                              hex(result.absolute_address)
                                              ))
        script = session.create_script(genscript(FUNCTIONS[lookup.index(f)],
                                                 result))
        script.on('message', on_message)
        script.load()
    log.info("Injected all needed scripts, now listening")
    sys.stdin.read()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        try:
            log.error("Usage: %s <process name or PID>" % __file__)
        except:
            sys.exit(-1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    main(target_process)
