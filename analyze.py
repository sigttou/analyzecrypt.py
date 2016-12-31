#!/usr/bin/env python2
import frida
import sys
from pwn import log

MODULES = ["libc.so", "libcrypto.so"]
LOOKFOR = "AES_cbc_encrypt"
SCRIPT = """
    Interceptor.attach(ptr("{}"), {{
        onEnter: function(args) {{
            send(args[0].toString(16));
        }}
    }});
"""


def on_message(message, data):
    if message['type'] == 'send':
        log.info(message['payload'])
    else:
        print(message)


def main(target):
    log.info("Going to analyze {}".format(target))
    session = frida.get_usb_device().attach(target)
    modules = session.enumerate_modules()

    # Get only needed Modules
    tmp = []
    for M in MODULES:
        tmp.append(modules[[x.name for x in modules].index(M)])
    modules = tmp

    functions = []
    for x in modules:
        functions += x.enumerate_exports()
    log.info("Found {} functions".format(len(functions)))

    result = functions[[x.name for x in functions].index(LOOKFOR)]
    log.info("Found {} in {} @ {}".format(result.name,
                                          result.module.name,
                                          hex(result.absolute_address)
                                          ))

    script = session.create_script(SCRIPT.format(result.absolute_address))
    script.on('message', on_message)
    script.load()
    sys.stdin.read()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        log.warning("Usage: %s <process name or PID>" % __file__)
        sys.exit(-1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    main(target_process)
