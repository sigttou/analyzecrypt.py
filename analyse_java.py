from __future__ import print_function

import itertools
import sys
import re
import os
import json

from pwn import log

"""
Try to monitor all methods of a class
"""

import frida

CONSTRUCTOR_METHOD = 1
STATIC_METHOD = 2
INSTANCE_METHOD = 3

CONFIG_FILE_NAME = "config/java.json"

CLASSES = [{"name": "javax.crypto.Cipher"},
           {"name": "javax.crypto.spec.IvParameterSpec"}]

jscode = """
Java.perform(function () {
    
    var c = null;
    try {
        c = Java.use('%s');
    }
    catch(err) {
        // class not found...
        send("<none>");
        return;
    }
    
    if (c !== null) {
        var cproto = Object.getPrototypeOf(c);    
        var members = Object.getOwnPropertyNames(cproto);
    }
    else {
        send("<none>");
        return;
    }
    
    method_list = [];
    
    for (var m in members) {
        var member = members[m];
        
        if (member !== '$className' && member !== '$new' && 'overloads' in c[member]) {
            // a method can have several overloads (same name, but different params)
            // therefore iterate over them
            for (var ovld in c[member].overloads) {
                method_list.push({'name': member, 'parameters': c[member].overloads[ovld].argumentTypes,
                                  'type': c[member].overloads[ovld].type, 'returnType': c[member].overloads[ovld].returnType});
            }
        }
    }
    
    send(method_list);
    
    // test hooking
    c.onEnter.overload().implementation = function() {
        send("onEnter called");
        return this.onEnter();
    }
    
});
"""

hook_jscode_header = """
Java.perform(function() {{

    var c = Java.use('{0}');
"""

hook_jscode = """
    c.{0}.overload({1}).implementation = function ({2}) {{
       var r=this.{0}.overload({1}).call({3});
       send({4});
       return r;
    }}
"""

hook_jscode_constructor = """
    c.{0}.overload({1}).implementation = function ({2}) {{
       this.{0}.overload({1}).call({3});
       send({4});
    }}
"""

hook_jscode_footer = """
    }); // end of Java.perform
"""

def _gen_hook_jscode_for_method(class_name, method_description):
    
    name = method_description["name"]
    return_type = method_description["returnType"]["className"]
    
    #if name == "$init":
    #    # do not hook $init (constructor) - causes problems (probably because of return value)
    #    return ""
        
    #if method_description["type"] == CONSTRUCTOR_METHOD:
    #    #TODO: don't know how to handle constructor methods
    #    return ""
    
    parameters = method_description["parameters"]
    signature_list = [p["className"] for p in parameters]
    num_parameters = len(parameters)    
    signature = ",".join("'{0}'".format(s) for s in signature_list)
      
    dummy_params_list = ["a{0}".format(i+1) for i in range(num_parameters)]
    dummy_params = ",".join(dummy_params_list)

    # for non-static methods, 'this' is the first parameter 
    if method_description["type"] != STATIC_METHOD:
        signature_list_and_this = [class_name] + signature_list
        this_and_dummy_params_list = ["this"] + dummy_params_list
    else:
        signature_list_and_this = signature_list
        this_and_dummy_params_list = dummy_params_list
    
    #needed for constructing the call to the original method
    this_and_dummy_params_string = ",".join(itertools.chain(["this"], dummy_params_list))

    param_info = ",".join("{{'name':'{0}','content':{0},'type':'{1}'}}".format(n,t) for n,t in zip(this_and_dummy_params_list, signature_list_and_this))

    #use slightly different code for special method $init, although the general hook code also seemed to work
    if name == "$init":
        fstring = "{{'name': '{0}.{1}', 'parameters':[{2}], 'returns':{{'type':'{3}'}} }}".format(class_name, name, param_info, return_type)
        return hook_jscode_constructor.format(name, signature, dummy_params, this_and_dummy_params_string, fstring)

    fstring = "{{'name': '{0}.{1}', 'parameters':[{2}], 'returns':{{'content':r,'type':'{3}'}} }}".format(class_name, name, param_info, return_type)
    
    return hook_jscode.format(name, signature, dummy_params, this_and_dummy_params_string, fstring)


def pretty_print(msg, print_function):
    """Print a monitoring message in a more readable way"""
    print_function("{0}:".format(msg["name"]))
    print_function("  parameters:")
    for entry in msg["parameters"]:
        print_function("    {0} ({1}): {2}".format(entry["name"], entry["type"], entry["content"]))
    print_function("  returns:")
    
    ret = msg["returns"]
    if "content" in ret:
        content = ret["content"]
    else:
        content = ""
        
    print_function("    ({0}): {1}".format(ret["type"], content))
    print_function("")

class Method_List_Receiver:
    """Retrieves methods of given classes and adds hooks for monitoring"""
    
    def __init__(self, process, config, path, callback_when_finished):
        self.class_counter = 0
        self.script = ""
        self.classes = config["classes"]
        self.print_calls = config["settings"]["print_calls"]
        self.write_results = config["settings"]["write_results"]
        self.callback = callback_when_finished
        self.process = process # frida process object
        self.num_classes = len(self.classes)
        
        self.path = path
        
    def start_hooking(self):
        log.info("Hooking classes. This may take a while...")
        self._hook_next()
    
    def _hook_next(self):
        if self.class_counter < self.num_classes:
            self.script = self.process.create_script(jscode % self.classes[self.class_counter]["name"])
            self.script.on('message', self._on_method_receive)
            self.script.load()
        else:
            self.callback()

    def _on_message(self, message, data):
        """Process the method call messages"""
        if message['type'] == 'send':
            #info = json.loads(str(message['payload']).encode('string-escape'), strict=False)
            info = message['payload']
            
            if self.print_calls:
                pretty_print(info, log.info)
                
            if self.write_results:
                filename = os.path.join(self.path, info["name"] + ".dat")
                with open(filename, "a+") as f:
                    json.dump(info, f)
                    f.write("\n")    
        else:
            log.warning(str(message).encode('string-escape'))

    def _on_method_receive(self, message, data):
        """After method list is received - upload the hook script"""
        
        class_counter = self.class_counter
        
        if message['type'] != 'send':
            return
        
        class_name = self.classes[self.class_counter]["name"]
        
        if message['payload'] != '<none>':
            method_list = message['payload']
            
            #print(method_list)
            
            self.script.unload()
            
            hook_script_code = (hook_jscode_header.format(class_name) + 
                                ''.join(_gen_hook_jscode_for_method(class_name, m) for m in method_list) +
                                hook_jscode_footer)
            
            #print(hook_script_code)
            
            hook_script = self.process.create_script(hook_script_code)
            hook_script.on('message', self._on_message)
            hook_script.load()
            
            log.info("Hooked methods of class {0}".format(class_name))
        else:
            log.info("Class {0} does not exist.".format(class_name))
            
        self.class_counter += 1
        self._hook_next()

def callback_when_finished():
    log.info("Finished hooking classes. Ready... Exit with CTRL-C")

def hook_classes(process, classes, path):    
    receiver = Method_List_Receiver(process, classes, path, callback_when_finished)
    receiver.start_hooking()

def main(target_process):
    
    with open(CONFIG_FILE_NAME) as j:
        config = json.load(j)
    
    try:
        session = frida.get_usb_device().attach(target_process)
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
    
    PATH = ""
    if config["settings"]["write_results"]:
        PATH = os.path.join(PATH, "results", sys.argv[1])
        if not os.path.exists(PATH):
            os.makedirs(PATH)

        runnr = len([x for x in os.listdir(PATH) if os.path.isdir(os.path.join(PATH,x))])
        PATH = os.path.join(PATH, "run_" + str(runnr))
        if not os.path.exists(PATH):
            os.makedirs(PATH)
            
    hook_classes(session, config, PATH)
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
