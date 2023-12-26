# pyvicemon
Python remote machine language monitor for the VICE C64 emulator

Connects to a running VICE instance (started with -binarymonitor) on 6502@127.0.0.1

## Files:
* vice_monitor.py - The monitor program
* miniasm6502.py - Standalone interactive assembler + disassembler, used by the monitor
  
## Commands:

* m - view (hex dump) memory
* d - disassemble memory
* a - assemble to memory
* r - view registers
* x - exit monitor (resume emulator)
* q - quit monitor and emulator

## TODO:
* breakpoints
* jump/goto address
* modify memory
* modify registers
* load binary data / .prg files / .sid files
* save binary data / .prg files
* fill memory
* ...more?

### Contributors welcome!
