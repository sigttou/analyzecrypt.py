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
	- read content from Addresses not only Strings
	- interconnect between functions(lengths, etc.)
- Support also Java functions not only C Libraries
- Monitor Memory Accesses (blocked by FRIDA: MemoryAccessMonitor is only available on Windows for now)
- Support multiple platforms (should be really easy)
- Analyse the results(!)
