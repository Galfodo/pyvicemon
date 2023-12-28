"""
VICE remote monitor. Use with VICE 3.5 or newer and '-binarymonitor' option.

Written by stein.pedersen@gmail.com

"""
# https://vice-emu.sourceforge.io/vice_12.html#SEC337

import os
import sys
import re
import socket
import select
import numpy as np
from enum import Enum
from typing import List, Dict

sys.path.append(os.path.realpath(os.path.split(sys.argv[0])[0]))
import miniasm6502
import psid

VERBOSE = False

VICE_SOCKET = None

PROMPT = "($[PROMPT_ADDR]) "
PROMPT_ADDR = 0
BREAK_ADDR = 0

MEMDUMP_DEFAULT_BYTES = 256

# Header
VICE_API_STX = 2
VICE_API_VERSION = 2

CMD_HEADER_DTYPE=[('ldx', np.uint8), ('api_version', np.uint8), ('body_size', np.uint32), ('request_id', np.uint32), ('cmd', np.uint8)]
CMD_HEADER_SIZE=np.zeros(1, dtype=CMD_HEADER_DTYPE).dtype.itemsize

CMD_RESPONSE_HEADER_DTYPE=[('ldx', np.uint8), ('api_version', np.uint8), ('body_size', np.uint32), ('response_type', np.uint8), ('error_code', np.uint8), ('request_id', np.uint32)]
CMD_RESPONSE_HEADER_SIZE=np.zeros(1, dtype=CMD_RESPONSE_HEADER_DTYPE).dtype.itemsize

RECV_BUFFER_SIZE = 100000

# Register name and ID must be queried through the VICE binary monitor interface
AVAILABLE_REGISTERS = {} # id: ('name', bit-size)
AVAILABLE_REGISTER_NAMES = {} # 'name': id

class MonCommand(Enum):
    memory_get              = 0x01
    memory_set              = 0x02
    checkpoint_get          = 0x11
    checkpoint_set          = 0x12
    checkpoint_delete       = 0x13
    checkpoint_list         = 0x14
    checkpoint_toggle       = 0x15
    condition_set           = 0x22
    registers_get           = 0x31
    registers_set           = 0x32
    dump                    = 0x41
    undump                  = 0x42
    resource_get            = 0x51
    resource_set            = 0x52
    advance_instructions    = 0x71
    keyboard_feed           = 0x72
    execute_until_return    = 0x73
    ping                    = 0x81
    banks_available         = 0x82
    registers_available     = 0x83
    display_get             = 0x84
    vice_info               = 0x85
    palette_get             = 0x91
    joyport_set             = 0xa2
    userport_set            = 0xb2
    exit                    = 0xaa
    quit                    = 0xbb
    reset                   = 0xcc
    autostart               = 0xdd

class MonResponse(Enum):
    MON_RESPONSE_MEMORY_GET              = 0x01
    MON_RESPONSE_MEMORY_SET              = 0x02
    MON_RESPONSE_CHECKPOINT_GET          = 0x11
    MON_RESPONSE_CHECKPOINT_SET          = 0x12
    MON_RESPONSE_CHECKPOINT_DELETE       = 0x13
    MON_RESPONSE_CHECKPOINT_LIST         = 0x14
    MON_RESPONSE_CHECKPOINT_TOGGLE       = 0x15
    MON_RESPONSE_CONDITION_SET           = 0x22
    MON_RESPONSE_REGISTER_INFO           = 0x31
    MON_RESPONSE_DUMP                    = 0x41
    MON_RESPONSE_UNDUMP                  = 0x42
    MON_RESPONSE_RESOURCE_GET            = 0x51
    MON_RESPONSE_RESOURCE_SET            = 0x52
    MON_RESPONSE_ADVANCE_INSTRUCTIONS    = 0x71
    MON_RESPONSE_KEYBOARD_FEED           = 0x72
    MON_RESPONSE_EXECUTE_UNTIL_RETURN    = 0x73
    MON_RESPONSE_PING                    = 0x81
    MON_RESPONSE_BANKS_AVAILABLE         = 0x82
    MON_RESPONSE_REGISTERS_AVAILABLE     = 0x83
    MON_RESPONSE_DISPLAY_GET             = 0x84
    MON_RESPONSE_VICE_INFO               = 0x85
    MON_RESPONSE_PALETTE_GET             = 0x91
    MON_RESPONSE_JOYPORT_SET             = 0xa2
    MON_RESPONSE_USERPORT_SET            = 0xb2
    MON_RESPONSE_EXIT                    = 0xaa
    MON_RESPONSE_QUIT                    = 0xbb
    MON_RESPONSE_RESET                   = 0xcc
    MON_RESPONSE_AUTOSTART               = 0xdd
    MON_RESPONSE_INVALID                 = 0x00                    
    MON_RESPONSE_JAM                     = 0x61
    MON_RESPONSE_STOPPED                 = 0x62    
    MON_RESPONSE_RESUMED                 = 0x63        

# Global response queue
RESPONSE_QUEUE = []

# Global request ID. Incremented by Command.__init__()
REQUEST_ID = 0

def format_request_id(item):
    return str(np.int32(item))

def format_response_type(item):
    return f'{MonResponse(item).name} ({item:02X})'

def format_cmd(item):
    return f'{MonCommand(item).name} ({item:02X})'

def format_32(item):
    return f'{item:08X}'

def format_default(item):
    return f'{item:02X}'

FIELD_FORMATTERS = {
    'cmd': format_cmd,
    'response_type': format_response_type,
    'body_size': format_32,
    'request_id': format_request_id,
    'default': format_default,
}

class InvalidCommand(RuntimeError):
    pass

class IncompletePackage(RuntimeError):
    pass

class ResponseNotFound(RuntimeError):
    pass

class Body(object):
    def __init__(self, data=b''):
        self._data = data

    def __repr__(self) -> str:
        return ' '.join([f'{int(i):02X}' for i in self._data])
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __bool__(self):
        return bool(self._data)
    
    @property
    def data(self):
        return self._data

class RegDump(Body):
    def __init__(self, data=b'', id_value_map: Dict = {}):
        super().__init__(data)
        self.id_value_map = { k: v&0xffff for k,v in id_value_map.items() }
        for id in id_value_map:
            assert id in AVAILABLE_REGISTERS

    def __getitem__(self, index: str) -> int:
        id = AVAILABLE_REGISTER_NAMES[index]
        return self.id_value_map[id]
    
    def __repr__(self) -> str:
        line0 = ''
        line1 = ''
        for id in self.id_value_map:
            name, width = AVAILABLE_REGISTERS[id]
            value = self.id_value_map[id] & 0xffff
            line0 += f'{name:<{width//4}} '
            line1 += f'{value:<0{width//4}X} '
        return f'{line0}\n{line1}'

class MemDump(Body):
    def __init__(self, address: int, data=b''):
        super().__init__(data)
        self.address = address

    def __repr__(self) -> str:
        tmp = super().__repr__()
        chunk_size = 16
        lines = [ tmp[i:i+chunk_size*3] for i in range(0, len(tmp), chunk_size*3) ]
        prefixes = [ f'{self.address + i*chunk_size:04X}:' for i in range(0, len(lines)) ]
        return '\n'.join([ prefix + data for prefix, data in zip(prefixes, lines) ])

def data_to_bytes(data = []):
    b = b''
    for i in data:
        if type(i) is int:
            b += bytes((i,))
        elif isinstance(i, Enum):
            b += bytes((i.value,))
        elif isinstance(i, bytes):
            b += i
        else:
            b += i.tobytes()
    return b

class Response(object):
    def __init__(self, header, body):
        self.header = header
        self.body = body

    def is_command_invalid(self):
        return self.header['response_type'] == MonResponse.MON_RESPONSE_INVALID.value
    
    def get_request_id(self):
        return int(self.header['request_id'])
    
    def __repr__(self):
        l = [ format_header(self.header.tobytes(), CMD_RESPONSE_HEADER_DTYPE, '  ') ]
        if self.body:
            l.append(f'  body: {repr(self.body)}')
        return '\n'.join(l)
    
class Command(object):
    def __init__(self, cmd: MonCommand, cmd_data: List):
        global REQUEST_ID
        REQUEST_ID += 1
        self.body = Body(data_to_bytes(cmd_data))
        self.header = np.zeros(1, dtype=CMD_HEADER_DTYPE)
        self.header['ldx'] = VICE_API_STX
        self.header['api_version'] = VICE_API_VERSION
        self.header['body_size'] = len(self.body)
        self.header['request_id']= REQUEST_ID
        self.header['cmd']= cmd.value
        self.binaryheader = self.header.tobytes()
        assert len(self.binaryheader) == 11
        self.blob = self.binaryheader + self.body.data

    def get_request_id(self):
        return int(self.header['request_id'])

    def __repr__(self):
        l = [ format_header(self.header.tobytes(), CMD_HEADER_DTYPE, '  ') ]
        if self.body:
            l.append(f'  body: {repr(self.body)}')
        return '\n'.join(l)

def indent_lines(lines: str, indent: str) -> str:
    return '\n'.join([indent + l for l in lines.splitlines()])

def log_received(response: Response) -> None:
    if VERBOSE:
        print('Received:')
        print(indent_lines(repr(response), '  '))
        print('')

def log_sending(command: Command) -> None:
    if VERBOSE:
        print('Sending:')
        print(indent_lines(repr(command), '  '))
        print('')

def create_command(cmd: MonCommand, cmd_data: List = []) -> Command:
    return Command(cmd, cmd_data)

def create_socket(address: str='127.0.0.1', port: int=6502, timeout: float=5.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((address, port))
    return sock

def get_socket():
    global VICE_SOCKET
    if not VICE_SOCKET:
        VICE_SOCKET = create_socket()
    return VICE_SOCKET

def send_command(command: Command) -> None:
    log_sending(command)
    get_socket().sendall(command.blob)
    
def parse_response(blob):
    """Generator function: Parse raw data to yield Response objects and finally None
    An IncompletePackage exception is raised if data is determined to be incomplete.
    If an unknown package is encountered, a RuntimeError is raised.
    """
    while blob:
        if len(blob) < CMD_RESPONSE_HEADER_SIZE:
            raise IncompletePackage()
        header = np.frombuffer(blob[:CMD_RESPONSE_HEADER_SIZE], dtype=CMD_RESPONSE_HEADER_DTYPE)
        if header['ldx'][0] != VICE_API_STX or header['api_version'][0] != VICE_API_VERSION:
            raise RuntimeError("Invalid header")
        remainder = blob[CMD_RESPONSE_HEADER_SIZE:]
        body_size = header['body_size'][0]
        if len(remainder) < body_size:
            raise IncompletePackage()
        yield Response(header, Body(remainder[:body_size]))
        blob = remainder[body_size:]
    yield None

def handle_response() -> None:
    """Receive data from the socket, parse it and put responses on the global RESPONSE_QUEUE"""
    packages = []
    resp = get_socket().recv(RECV_BUFFER_SIZE)
    while True:
        try:
            gen = parse_response(resp)
            package = next(gen)
            while package:
                log_received(package)
                packages.append(package)
                package = next(gen)
            break
        except IncompletePackage:
            resp = resp + get_socket().recv(RECV_BUFFER_SIZE)
            packages = []
    RESPONSE_QUEUE.extend(packages)

def response_pending() -> bool:
    readable, writable, errored = select.select([get_socket()],[],[], 0)
    return get_socket() in readable

def format_header(blob, dtype, indent = '') -> str:
    data_size = np.zeros(1, dtype=dtype).dtype.itemsize
    data = np.frombuffer(blob[:data_size], dtype=dtype)
    l = []
    for n, _ in dtype:
        fmt = FIELD_FORMATTERS[n] if n in FIELD_FORMATTERS else FIELD_FORMATTERS['default']
        field = fmt(data[n][0])
        desc = f'{indent}{n}: {field}'
        l.append(desc)
    return '\n'.join(l)

def pop_response(request_id: int) -> MonResponse:
    for i, response in enumerate(RESPONSE_QUEUE):
        if response.get_request_id() == request_id:
            if response.is_command_invalid():
                response = RESPONSE_QUEUE.pop(i)
                raise InvalidCommand(repr(response))
            return RESPONSE_QUEUE.pop(i)
    raise ResponseNotFound(f'request_id: {request_id}')

def roundtrip_command(cmd: MonCommand, cmd_data: List=[], await_response=True) -> MonResponse:
    command = create_command(cmd, cmd_data)
    send_command(command)
    request_id = command.get_request_id()
    while await_response:
        try:
            handle_response()
            return pop_response(request_id)
        except ResponseNotFound:
            pass

class MEMSPACE(Enum):
    MEM_MAIN = 0
    MEM_DRV_8 = 1
    MEM_DRV_9 = 2
    MEM_DRV_10 = 3
    MEM_DRV_11 = 4

def read_memory(address: int, count: int = 1, side_effects: bool = False, memspace: MEMSPACE = MEMSPACE.MEM_MAIN, bankid: int = 0) -> MemDump:
    cmd_data = [ 1 if side_effects else 0, np.uint16(address), np.uint16((address + count - 1)&0xffff), memspace.value, np.uint16(bankid) ]
    response = roundtrip_command(MonCommand.memory_get, cmd_data)
    return MemDump(address, response.body.data[2:])

def write_memory(address: int, data: bytes = b'', side_effects: bool = False, memspace: MEMSPACE = MEMSPACE.MEM_MAIN, bankid: int = 0) -> Response:
    cmd_data = [ 1 if side_effects else 0, np.uint16(address), np.uint16((address + len(data) - 1)&0xffff), memspace.value, np.uint16(bankid), data ]
    response = roundtrip_command(MonCommand.memory_set, cmd_data)
    return response

def get_registers_available(memspace: MEMSPACE = MEMSPACE.MEM_MAIN) -> None:
    AVAILABLE_REGISTERS.clear()
    AVAILABLE_REGISTER_NAMES.clear()
    cmd_data = [ memspace.value ]
    response = roundtrip_command(MonCommand.registers_available, cmd_data)
    data: bytes = response.body.data
    item_count = np.frombuffer(data[:2], dtype=np.uint16)[0]
    item_offset = 2
    for i in range(0, item_count):
        item_size   = int(data[item_offset + 0])
        reg_id      = int(data[item_offset + 1])
        reg_bitsize = int(data[item_offset + 2])
        name_len    = int(data[item_offset + 3])
        reg_name    = data[item_offset + 4:item_offset + 4 + name_len].decode()
        AVAILABLE_REGISTERS[reg_id] = (reg_name, reg_bitsize)
        AVAILABLE_REGISTER_NAMES[reg_name] = reg_id
        item_offset += item_size + 1

def get_registers(memspace: MEMSPACE = MEMSPACE.MEM_MAIN) -> RegDump:
    if not AVAILABLE_REGISTERS:
        get_registers_available()
    cmd_data = [ memspace.value ]
    response = roundtrip_command(MonCommand.registers_get, cmd_data)
    data: bytes = response.body.data
    item_count = np.frombuffer(data[:2], dtype=np.uint16)[0]
    item_offset = 2
    registers = {}
    for i in range(0, item_count):
        item_size   = int(data[item_offset + 0])
        reg_id      = int(data[item_offset + 1])
        reg_value   = np.frombuffer(data[item_offset + 2:item_offset + 4], dtype=np.uint16)[0]
        registers[reg_id] = reg_value
        assert item_size == 3
        item_offset += item_size + 1
    return RegDump(data, registers)

def set_registers(name_value_map: Dict[str, int], memspace: MEMSPACE = MEMSPACE.MEM_MAIN) -> Response:
    cmd_data = [ memspace.value, np.uint16(len(name_value_map)) ]
    for name, value in name_value_map.items():
        id = AVAILABLE_REGISTER_NAMES[name]
        value = np.uint16(value & 0xffff)
        cmd_data.extend([3, id, value])
    response = roundtrip_command(MonCommand.registers_set, cmd_data)
    return response

def monitor_ping():
    return roundtrip_command(MonCommand.ping)

def monitor_exit():
    return roundtrip_command(MonCommand.exit)

def monitor_quit():
    return roundtrip_command(MonCommand.quit)

while response_pending():
    handle_response()

def dumpregs():
    regs = get_registers()
    print(regs)
    print()
    return regs

WORD_PAT = '([0-9a-fA-F]{1,4})'
BYTE_PAT = '([0-9a-fA-F]{1,2})'
STR_PAT  = '(".*")'

def int_16(token: str) -> int:
    return int(token, base=16)&0xffff

def parse_token(token: str, pat, converter=int_16):
    m = re.match(pat, token)
    if m:
        value = converter(m[1])
        return True, value
    return False, None

def consume_word_token(input_tokens: List[str], default_or_none: None, name: str = '<address>') -> int:
    if input_tokens:
        token = input_tokens.pop(0)
        ok, value = parse_token(token, WORD_PAT, int_16)
        if ok:
            return value
        else:
            raise SyntaxError(f'Invalid token "{token}". Please specify a 16-bit hexadecimal number for "{name}".')
    elif default_or_none is not None:
        return default_or_none
    else:
        raise SyntaxError(f'Please specify a 16-bit hexadecimal number for "{name}"')

def consume_lastaddr_token(input_tokens: List[str], default_or_none: None, name: str = '<last-address>', firstaddr: int=0, first_name: str = '<first-address>') -> int:
    lastaddr = consume_word_token(input_tokens, default_or_none, name)
    if lastaddr < firstaddr:
        raise ValueError(f'"{name}" must be greater or equal to "{first_name}"')
    return lastaddr

def consume_string_token(input_tokens: List[str], default_or_none: None, name: str='<string>') -> str:
    if input_tokens:
        token = input_tokens.pop(0)
        if token.startswith('"') and token.endswith('"'):
            return token[1:-1]
        return token
    if default_or_none is None:
        raise SyntaxError(f'Please specify a string value for {name}')
    return default_or_none

def parse_cmd_m(input_tokens: List[str]) -> None:
    global PROMPT_ADDR
    first = PROMPT_ADDR
    last = PROMPT_ADDR + MEMDUMP_DEFAULT_BYTES - 1
    first = consume_word_token(input_tokens, first, '<first-address>')
    last = consume_lastaddr_token(input_tokens, first + MEMDUMP_DEFAULT_BYTES - 1, '<last-address>', first, '<first-address>')
    mem = read_memory(first, last-first+1)
    print(mem)
    PROMPT_ADDR = last + 1

DISASM_DEFAULT_LINES = 25

def parse_cmd_d(input_tokens: List[str]) -> None:
    global PROMPT_ADDR
    first = consume_word_token(input_tokens, PROMPT_ADDR, '<address>')
    mem = read_memory(first, DISASM_DEFAULT_LINES*3)
    text, remainder = miniasm6502.disasm_blob(first, mem.data, max_lines=DISASM_DEFAULT_LINES)
    print(text)
    PROMPT_ADDR = first + len(mem.data) - len(remainder)

def parse_cmd_r(input_tokens: List[str]) -> None:
    regs = get_registers()
    print(regs)

def parse_cmd_a(input_tokens: List[str]) -> None:
    first = consume_word_token(input_tokens, None, '<address>')
    first, data = miniasm6502.interactive(first, quit_on_empty_input=True, prefix=' '.join(input_tokens))
    if data:
        write_memory(first, data)

def parse_cmd_wm(input_tokens: List[str]) -> None:
    global PROMPT_ADDR
    first = consume_word_token(input_tokens, None, '<address>')
    cmd_data = []
    for t in input_tokens:
        if len(t) > 2:
            cmd_data.append(np.uint16(int(t,base=16)&0xffff))
        else:
            cmd_data.append(int(t,base=16)&0xff)
    if cmd_data:
        data = data_to_bytes(cmd_data)
        write_memory(first, data)
        PROMPT_ADDR = first + len(data)

def load_file(filename:str, load_addr: int = 0, no_header: bool = False):
    """Load a binary file.
    
    Unless the no_header parameter is True, this function interprets .prg and .sid
    files as if they have a header and only the load address and payload is returned.

    .prg files are assumed to have a 2-byte header that specifies the load address.
         This can be overridden by specifying a nonzero load address.

    .sid files are assumed to be of the PSID format.

    All other files are assumed to be raw binary files.
    """
    with open(filename, 'rb') as infile: data = infile.read()
    if filename.upper().endswith(".PRG") and not no_header:
        if load_addr == 0:
            load_addr = np.frombuffer(data[:2], dtype=np.uint16)
        return int(load_addr), data[2:]
    if filename.upper().endswith(".SID") and not no_header:
        sid = psid.load_sid(filename)
        print(sid)
        return load_addr or sid.get_load_address(), sid.get_body()
    return load_addr, data
    
MONITOR_HELP = """Monitor help:

Commands:
"""

def parse_cmd_help(input_tokens: List[str]) -> None:
    print(MONITOR_HELP)
    for name in COMMAND_PARSERS:
        _, info, args = COMMAND_PARSERS[name]
        print(f'{name:<4} {args:30} {info}')
    print("\nAll numeric operands are assumed to be hexadecimal")

def parse_cmd_s(input_tokens: List[str]) -> None:
    raise NotImplementedError()

def parse_cmd_g(input_tokens: List[str]) -> None:
    global BREAK_ADDR
    addr = consume_word_token(input_tokens, BREAK_ADDR, '<address>')
    set_registers({"PC": addr})
    monitor_exit()

def parse_cmd_l(input_tokens: List[str]) -> None:
    filename = consume_string_token(input_tokens, None, '<filename>')
    load_addr = consume_word_token(input_tokens, 0, '<load-address>')
    load_addr, body = load_file(filename, load_addr=load_addr)
    write_memory(load_addr, body)
    print(f'Loaded "{os.path.split(filename)[1]}" from ${load_addr:04X} to ${load_addr+len(body)-1:04X}')

def parse_cmd_b(input_tokens: List[str]) -> None:
    raise NotImplementedError()

def parse_cmd_resume(input_tokens: List[str]) -> None:
    monitor_exit()

COMMAND_PARSERS = {
    "x": (None,                 "exit interactive mode and resume emulator", ""),
    "q": (None,                 "exit interactive mode and quit emulator", ""),
    "g": (parse_cmd_g,          "go (to address)", "[address]"),
    "m": (parse_cmd_m,          "list memory", "[first-address] [last-address]"),
    "r": (parse_cmd_r,          "dump register contents", ""),
    "d": (parse_cmd_d,          "disassemble memory", "[address]"),
    "a": (parse_cmd_a,          "assemble to memory", "<address>"),
    ">": (parse_cmd_wm,         "write data to memory", "<address> [data] ..."),
    "s": (parse_cmd_s,          "save memory to disk", '<"filename.prg"> <first-address> <last-address>'),
    "l": (parse_cmd_l,          "load file to memory", '<"filename.prg"> [load-address]'),
    "b": (parse_cmd_b,          "set breakpoint", "<address>"),
    "+": (parse_cmd_resume,     "resume execution in emulator", ""),

    "help": (parse_cmd_help,    "display help", ""),
}

def tokenize(input: str) -> List[str]:
    # This is pretty primitive, but works for now
    tok=[]
    items = input.split()
    it = iter(input.split())
    for t in it:
        if t.startswith('\"'):
            while not t.endswith('\"'):
                t += ' '
                t += next(it)
        tok.append(t)
    return tok

def interactive():
    global PROMPT
    global PROMPT_ADDR
    global BREAK_ADDR
    regs = dumpregs()
    BREAK_ADDR = PROMPT_ADDR = regs['PC']
    prev_command = ''
    while True:
        prompt = PROMPT.replace('[PROMPT_ADDR]', f'{PROMPT_ADDR&0xffff:04X}')
        print(prompt, end='')
        sys.stdout.flush()
        input = sys.stdin.readline().strip()
        if input == 'q':
            monitor_quit()
            return None
        elif input == 'x':
            monitor_exit()
            return None
        else:
            if not input:
                input = prev_command
            tokens = tokenize(input)
            if tokens:
                # If there is no space between the command and the first operand, find the longest matching command name
                # and split it from the operand
                if not tokens[0] in COMMAND_PARSERS:
                    t = tokens[0]
                    for i in range(len(t)-1, 0, -1):
                        if t[:i] in COMMAND_PARSERS:
                            tokens[0:1] = [ t[:i], t[i:] ]
                            input = ' '.join(tokens) # In case we have a string token, re-tokenize
                            tokens = tokenize(input)
                            break
                if tokens[0] in COMMAND_PARSERS:
                    try:
                        parser, _, _ = COMMAND_PARSERS[tokens[0]]
                        parser(tokens[1:])
                        prev_command = input
                    except SyntaxError as e:
                        print(e)
                    except ValueError as e:
                        print(e)
                    except NotImplementedError:
                        print(f'Command "{tokens[0]}" is not yet implemented.')
                else:
                    print(f'Unknown command "{tokens[0]}"')

def main():
    interactive()

if __name__ == "__main__":
    main()
