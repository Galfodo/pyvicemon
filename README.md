# pyvicemon
Remote machine language monitor for the VICE C64 emulator, implemented in Python

Connects to a running VICE instance (started with -binarymonitor) on 6502@127.0.0.1

When used from a Python script or interactive session, the various debugging functions 
(e.g `set_breakpoint()`, `wait_for_debugger_event()`, `read_memory()`, `write_memory()`, `load_file()`
`save_file()`, etc.) can be used for complex debugging scenarios and capturing state in an automated
fashion.

## Files:
* vice_monitor.py - The monitor program
* miniasm6502.py - Standalone interactive assembler + disassembler, used by the monitor
* psid.py - For reading .sid files

## Command line arguments:
```
  -h, --help            show this help message and exit
  -s SESSION, --session SESSION
                        Playback session
  -r RECORD, --record RECORD
                        Record session to file.
  -i, --interactive     Enter interactive mode. This is the default if no
                        commands are specified.
  --monitor-help        List monitor commands.
```
## Interactive monitor commands:
```
x                                                                 exit interactive mode and resume emulator
q                                                                 exit interactive mode and quit emulator
g    [address]                                                    go (to address)
m    [first-address] [last-address]                               list memory
r                                                                 dump register contents
d    [address]                                                    disassemble memory
a    <address>                                                    assemble to memory
>    <address> [data] ...                                         write data to memory
s    <filename.prg> <first-address> <last-address> [load-address] save memory to disk
l    <filename.prg> [load-address]                                load file to memory
b    <first-address> [last-address]                               set execution breakpoint
br   <first-address> [last-address]                               set data breakpoint (read)
bw   <first-address> [last-address]                               set data breakpoint (write)
c    [timeout (seconds, decimal)]                                 continue and wait for debugger event
help                                                              display help

All numeric operands are assumed to be hexadecimal unless otherwise specified
```
## TODO:
* breakpoint conditions
* modify registers
* fill memory
* find
* ...more?
