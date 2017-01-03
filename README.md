# analyzecrypt.py
Python application used to monitor function calls on Android via [Frida](https://www.frida.re).

## Setup
- Get an own env for your python project (run in the repo folder)
```
$ virtualenv-2.7 --distribute --no-site-packages venv
$ source venv/bin/activate
(venv) $ pip install pwn frida
```

## Configuration
- Add needed modules to `config/modules.json`
- Add functions which you monitor in `functions` look at given files as examples

## Documentation 
The code is enough, it's just some lines.

## TODO:
- More monitoring options:
	- read content from addresses not only strings
		- support structs like functions
	- interconnections between functions(lengths, etc.)
- Support Java functions not only C libraries
- Monitor memory accesses (blocked by Frida: MemoryAccessMonitor is only available on Windows for now)
	- could be done on function calls if same address is given check for content changes
- Support multiple platforms (should be really easy - Frida supports it)
- Get information directly from C/Java code (Use [pycparser](https://github.com/eliben/pycparser)/a java code analyzer for example)
	- finished for C headers, see `get_functions.py`
- Analyse the results
