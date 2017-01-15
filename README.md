# analyzecrypt.py
Python application used to monitor function calls (C or Java) on Android via [Frida](https://www.frida.re).

## Setup
- Get an own env for your python project (run in the repo folder)
```
$ virtualenv-2.7 --distribute --no-site-packages venv
$ source venv/bin/activate
(venv) $ pip install pwn frida pycparser
```

## Configuration (C calls)
- Add needed modules to `config/modules.json`
- Add functions which you monitor in `functions` look at given files as examples
	- Or use `get_functions.py` with C code you wish to analyse.

## Configuration (Java method calls)
- Add classes to trace to `config/java.json`.
- The `analyse_java.py` script will trace all methods of the given classes: 
methods are automatically discovered

## Documentation 
The code is enough, it's just some lines.

## Using the code
Run `analyze.py` to trace C function calls using Frida.
Run `analyze_java.py` to trace Java method calls using Frida.
Use `eval_results.py` to get information about the logged calls

## TODO:
- Integration of C and Java tracer into one tool: trace C and Java calls
at the same time
- C: More monitoring options:
	- read content from addresses not only strings
		- support structs like functions
	- interconnections between functions(lengths etc.)
		- support return value of calls (onLeave e.g.)
- Monitor memory accesses (blocked by Frida: MemoryAccessMonitor is only available on Windows for now)
	- could be done on function calls if same address is given check for content changes
- Support multiple platforms (should be really easy - Frida supports it)
- Get information directly from C/Java code (Use [pycparser](https://github.com/eliben/pycparser)/a java code analyzer for example)
	- done for C headers, see `get_functions.py`
		- still needs improvement for more complex headers, like `socket.h`
- Analyse the results
  - done for really simple analysis, still needs improvement
    - double warning if multiple usages across calls
    - infomation lacks quality
    - should also work over multiple function
- Automated module search (No need to set them manually in the config, can already be done but is really slow)
- Fix string representation in results to show hex code instead of unicode
- Java: allow to select methods to trace using regex instead of hooking all methods by default

