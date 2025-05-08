# Binary exploitation and Reverse engineering utils

# Stack frame

When a function is **called**:
- A new `stack frame` is pushed onto the stack.
- It contains:
    - `Return address` (where to resume after the function ends)
    - Saved `base pointer` (previous frame’s base)
    - `Function arguments`
    - `Local variables`

When the function **returns**:
- Its stack frame is `popped off` the stack.
- The `base pointer` (`ebp`, `rbp`) is `restored`.
- The `instruction pointer` (`eip`, `rip`) `jumps back to the return address`.

- https://stackoverflow.com/questions/3699283/what-is-stack-frame-in-assembly


## Prologue & Epilogue

- https://en.wikipedia.org/wiki/Function_prologue_and_epilogue

A function **prologue** typically does the following actions if the architecture has a base pointer (also known as frame pointer) and a stack pointer:
- Pushes current base pointer onto the stack, so it can be restored later.
- Value of base pointer is set to the address of stack pointer (which is pointed to the top of the stack) so that the base pointer will point to the top of the stack.
- Moves the stack pointer further by decreasing or increasing its value, depending on whether the stack grows down or up. On x86, the stack pointer is decreased to make room for the function's local variables.

```
    push ebp
    mov	ebp, esp
    sub	esp, N
```

Function **epilogue** reverses the actions of the function prologue and returns control to the calling function. It typically does the following actions (this procedure may differ from one architecture to another):
- Drop the stack pointer to the current base pointer, so room reserved in the prologue for local variables is freed.
- Pops the base pointer off the stack, so it is restored to its value before the prologue.
- Returns to the calling function, by popping the previous frame's program counter off the stack and jumping to it.

```
    mov	esp, ebp
    pop	ebp
    ret
```

## Example

Let's look at a simple example. We will take the function `foo (a, b, c)` and see how it is represented as assembly instructions and observe the stack's behavior:
```
; Instructions:
1 push c
2 push b
3 push a 
4 call foo <- we are here
5 ...

; Stack:
0x8 a
0x9 b
0xa c
```

When the `call foo` is executed. The `call` instruction do 2 things:
- Push `eip` on the stack as the next instruction to execute when the function return (the return address)
- And jump on the function `foo`:
```
; Instructions for 'call'
    push eip
    jmp foo

; Instructions:
1 push c
2 push b
3 push a
4 call foo <- we are here
5 ...

; Stack:
0x7 ret_addr (line 5) <-esp
0x8 a
0x9 b
0xa c
``` 

In `foo` the **prologue** instructions are executed to save the start of the previous `stack frame` and the `stack` is updated:
```
; Instructions in the previous stack frame:
1 push c
2 push b
3 push a
4 call foo <- we are in foo instructions (eip is saved in the stack so we know that we need to continue line 5)
5 ...

; Instructions in foo:
1 push ebp
2 mov	ebp, esp
3 ... <- current execution 

; Stack:
0x6 prev_base_pointer <- esp - ebp
0x7 ret_addr (line 5)
0x8 a
0x9 b
0xa c
```

The memory layout will look like this for each stack frame:
```
+-------------------+ <-- esp before call
|   argument 2      |
+-------------------+
|   argument 1      |
+-------------------+
| return address    |
+-------------------+
| old EBP (saved)   | <-- ebp after prologue
+-------------------+
| local variable    | <-- esp after prologue
+-------------------+
```

# GDB

## Commands

- `x/x addr` # display an address in hex
- `x/b addr` # display the first byte of the address
- `x/xw addr` # display the address as a 'word'
- `x/xg addr` # display the 8 bytes addresses (x64)
- `p/d addr1 - addr2` # return the differences of 2 addresses

- `info proc map` # show the memory address space ranges accessible in a process
```
Start Addr   End Addr       Size     Offset objfile
       0x10000    0x15000     0x5000        0x0 /bin/true
...
```

# Protections

## RELRO - Relocation Read-Only
[Relocation Read-Only](https://ctf101.org/binary-exploitation/relocation-read-only/) (or RELRO) is a security measure which `makes some binary sections read-only`. There are `2 modes`: </br>
- **Partial RELRO**:
    - Default setting in GCC
    - Forces the GOT to come before the BSS in memory, eliminating the risk of a buffer overflows on a global variable overwriting GOT entries.
```
gcc -no-pie -Wl,-z,relro -o binaire source.c # -no-pie needed
```

- **FULL RELRO**:
    - `Makes the entire GOT read-only which removes the ability to perform a "GOT overwrite" attack`
    - Not a default compiler setting as it can greatly increase program startup time since all symbols must be resolved before the program is started
    - Enabled by default

Can be disabled with:
```
gcc -Wl,-z,norelro -o binaire source.c
```


## STACK CANARY

[Stack Canaries](https://ctf101.org/binary-exploitation/stack-canaries/) are a `secret value placed on the stack which changes every time the program is started`. Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immeadiately. (Disabled by default)</br>

```
gcc -fstack-protector-all -o binaire source.c # Enable it
gcc -fno-stack-protector -o binaire source.c # Disable it
```

### Bypassing Stack canaries

Stack Canaries seem like a clear cut way to mitigate any `stack smashing` as it is fairly impossible to just guess a random 64-bit value. However, `leaking` the address and `bruteforcing` the canary are two methods which would allow us to get through the canary check: </br>
- **Stack Canary Leaking**
    - `If we can read the data in the stack canary, we can send it back to the program later because the canary stays the same throughout execution.` </br>

    - `Linux` makes this slightly tricky by `making the first byte of the stack canary a NULL`, meaning that string functions will stop when they hit it.
        - A method around this would be to `partially overwrite` and then put the NULL back or find a way to leak bytes at an arbitrary stack offset.

- **Bruteforcing a Stack Canary**

    - The `canary is determined when the program starts up for the first time` which means that if the program `forks`, it `keeps the same stack cookie in the child process`. This means that if the input that can overwrite the canary is sent to the child, we can use whether it crashes as an oracle and brute-force 1 byte at a time! [Read more](https://ctf101.org/binary-exploitation/stack-canaries/)

## NX - No eXecute

The [No eXecute](https://ctf101.org/binary-exploitation/no-execute/) or the NX bit (also known as Data Execution Prevention or DEP) `marks certain areas of the program as not executable`, meaning that `stored input or data cannot be executed as code`. This is significant because it prevents attackers from being able to jump to custom shellcode that they've stored on the stack or in a global variable. (Enabled by default)

```
gcc -z noexecstack -o binaire source.c # Enable
gcc -z execstack -o binaire source.c # Disable
```

## PIE - Position Independent Executables

Enabled by default.

```
gcc -fPIE -pie -o binaire source.c # Enable
gcc -no-pie -o binaire source.c # Disable
```


## More documentations
Adress Space Layout Randomization - G. Lettieri https://lettieri.iet.unipi.it/hacking/aslr-pie.pdf </br>
Nightmare Intro to Reverse - https://guyinatuxedo.github.io/00-intro/index.html </br>


## Useful ressources
Hex to Dec converter - https://www.rapidtables.com/convert/number/hex-to-decimal.html </br>
Hex calculator - https://www.calculator.net/hex-calculator.html </br>
Linux System Call Table - https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit </br>
Hex to String converter - https://codebeautify.org/hex-string-converter </br>
XOR calculator - https://xor.pw/# </br>
Ascii table code - https://www.ascii-code.com/ </br>
x86 / x64 Assembler and Disassembler - https://defuse.ca/online-x86-assembler.htm </br>

