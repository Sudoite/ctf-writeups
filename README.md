# ctf-writeups

This is a repository of writeups for various CTF challenges. I am intentionally leaving in discussion about where I made mistakes or went down blind alleys, as such occasions can be great learning experiences, both for the person solving the challenge and potentially for the person reading the writeup. I hope they are informative and entertaining! To read a write-up, just click through to the `.md` file with the same name as the challenge.

Here are some of my favorites:

1. [Turtles](./CSAW2018/turtles) (CSAW 2018): an entertaining Objective-C exploit that makes use of heap exploitation, format string attacks, and a buffer overflow / ROP chain.

2. [Leakless](./FireshellCTF2019/leakless) (Fireshell CTF 2019): a manual implementation of an attack that hijacks dynamic symbol resolution in Linux.

3. [Choose](./PicoCTF2017/final) (PicoCTF 2017 final challenge): I independently discovered a (possibly well-known) approach for bypassing a stack canary using characteristics of memory alignment for C structs in the GCC compiler.

4. [ECC2](./PicoCTF2017/ECC2) (PicoCTF 2017): this solution to an elliptic curve cryptography problem uses the Pohlig-Hellman algorithm.

5. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): an unintended solution to a ROP chain / reverse engineering problem involving a clever way to get a large value into the `rbx` register despite an apparent dearth of ROP gadgets containing `rbx`. That sets up a call to `read` and subsequent pivot to the `.bss` section to continue the ROP chain.

6. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): Overwrite a `libc` writable exit handler hook to loop back to the main function and set up a ROP chain. There were many creative solutions to this challenge.


## By category and technique

### Pwnable Challenges

#### Heap Exploitation

1. [Turtles](./CSAW2018/turtles): Squeezing as many fake smallbins as possible into a small space on the heap; writing a ROP chain that will work despite part of it getting copied from the stack to the heap, potentially corrupting the heap

2. [Chat Logger](./PicoCTF2017/chat-logger) (PicoCTF 2017): abuse a bug in the program to change the maximum length of a message, then edit a short message to overwrite a subsequent chunk in the heap

3. [Enter the Matrix](./PicoCTF2017/matrix) (PicoCTF 2017): Exploit a bug in how rows and columns of a matrix are accessed to write beyond a chunk's boundary

4. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): get `calloc` to return a null pointer by allocating too much memory, and exploit the null pointer

5. [Heap Golf](./SwampCTF2019/heapgolf) (Swamp CTF 2019): simple heap problem illustrating how fastbins work


###### Use After Free

1. [Aggregator](./PicoCTF2017/aggregator) (PicoCTF 2017): Overwriting the Global Offset Table using Use After Free

2. [Contact Helper](./PicoCTF2017/contact-helper) (PicoCTF 2017): unintended solution to a heap exploitation problem with a UAF vulnerability.

#### ROP Chain

1. [Turtles](./CSAW2018/turtles) (CSAW2018): use of One Gadget

2. [OTP-Server](./FacebookCTF2019) (FaceBook CTF 2019): write a ROP chain one byte at a time using random bytes with values I can test

3. [Overfloat](./FacebookCTF2019) (FaceBook CTF 2019): ROP chain that works with 32-bit floats

4. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): same idea as [Overfloat](./FacebookCTF2019/overfloat), but with full RELRO protection

4. [Leakless](./FireshellCTF2019/leakless) (Fireshell CTF 2019): attacking dynamic symbol lookup in ELF binaries, with a full explanation of the technique

5. [pwn5](./TAMUCTF2019/pwn5) (TAMUCTF 2019): simple intro-level ROP problem

6. [Defcon Quals Speedrun 2](./DefConQuals2019/speedrun2/README.md) (DEF CON Quals 2019): ROP problem without a `libc` version provided

7. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): Unintended solution involving a clever way to move a large value into `rbx` while setting up a pivot to the `.bss` section with a call to `read`.

8. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): Overwrite a `libc` writable hook for an exit handler to loop back to the main function and set up a ROP chain.

##### Statically-linked binary

1. [Defcon Quals Speedrun 1](./DefConQuals2019/speedrun1) (DEF CON Quals 2019): simple ROP problem

2. [ropberry](./INSHack2019/pwn/ropberry): 64-bit ROP chain

3. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): 64-bit ROP chain and statically-linked binary, but definitely non-trivial!

#### Format Strings

1. [Turtles](./CSAW2018/turtles) (CSAW2018): straightforward info leak

2. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): bypass a canary using a format string leak

3. [Flagsay-2](./PicoCTF2017/flagsay-2) (PicoCTF 2017): straightforward overwrite of the Global Offset Table


#### Shellcode

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): 32-bit ARM shellcode

2. [Choose](./PicoCTF2017/final) (PicoCTF 2017): 32-bit Linux `x86` shellcode to execute `execve`, split into 11-byte sections and using relative jumps to string the shellcode together

3. [pwn3](./TAMUCTF2019/pwn3) (TAMUCTF 2019): simple Linux `x86` shellcode, executed on the stack

4. [gimmeyourshell](./INSHack2019/pwn/gimmeyourshell) (INSHack 2019): Linux `x86-64` shellcode, executed on the stack

#### Bypassing stack canaries

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): bypass a canary using a format string leak

2. [Choose](./PicoCTF2017/final) (PicoCTF 2017): bypass a canary using "holes" in C structs generated by the GCC compiler for alignment reasons

3. [quicksort](./StarCTF2019/quicksort) (`*CTF2019`): A vulnerability in the C code allows function pointers to be overwritten -- but whatever then gets written is subsequently treated as a list of integers and sorted in place, leading to a creative specification of the `/bin/sh` string in order to execute `system("/bin/sh")`.

#### Bypassing full RELRO

1. [Deeper Into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): bypass full RELRO protection by writing to a writable hook to `malloc`, `calloc`, or `free` in `libc`


#### Simple Buffer Overflow

1. [pwn1](./TAMUCTF2019/pwn1) (TAMUCTF 2019): trivial, speedrun-type problem

2. [big_boi](./CSAW2018/bigboi) (CSAW CTF 2018): very simple, overwrite an integer with another

3. [pwn2](./TAMUCTF2019/pwn2) (TAMUCTF 2019): return to a function to print the flag

4. [get-it](./CSAW2018/get_it) (CSAW CTF 2018): partial overwrite of the return address to print the flag

5. [warm](./VolgaCTF2019/warm) (VolgaCTF Quals 2019): overwrite a file name to open an arbitrary file on the server


### Cryptography Challenges

1. [ECC2](./PicoCTF2017/ECC2) (PicoCTF 2017): elliptic curve cryptography problem, solved with the Pohlig-Hellman algorithm

2. [Encrypted Shell](./PicoCTF2017/encrypted-shell) (PicoCTF 2017): Application of Pollard's kangaroo algorithm to solve the discrete log problem to get a private key for the Diffie-Hellman public key exchange protocol. (Not an original solution.)

3. [Blind](./VolgaCTF2019/blind) (Volga CTF Quals 2019): Implementation of an RSA blinding attack

4. [eleCTRic](./PicoCTF2018/crypto/eleCTRic) (PicoCTF 2018): An attack on an improperly-implemented version of AES using counter mode.

### Reverse Engineering Challenges

1. [MIPS](./PicoCTF2017/MIPS) (PicoCTF 2017): reversing a MIPS binary containing branch-delay slots; usage of the SPIM simulator

2. [Forest](./PicoCTF2017/forest) (PicoCTF 2017): Straightforward problem reversing a binary that looks up symbols in a tree to generate a message.

3. [Much Ado About Hacking](./PicoCTF2017/much-ado) (PicoCTF 2017): decompiling a program written in the Shakespeare Programming Language

4. [Warm](./VolgaCTF2019/warm) (VolgaCTF Quals 2019): this is a pwnable challenge, but it shows how easy it is to use Ghidra to reverse an ARM executable

5. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): This pwnable challenge requires reverse-engineering some code and satisfying a set of constraints to compute a secret key, in order to proceed to the actual vulnerable section of the code.

### Web Challenges

1. [A Kaley Ceilidh](./PicoCTF2017/kaley-ceilidh) (PicoCTF 2017): A blind NoSQL injection attack on a server running MongoDB and NodeJS. Also covers Http requests in Python. (Solved with hints from other sources)

2. [Artisinal Hand-Crafted HTTP3](./PicoCTF2018/web/ArtisinalHTTP3) (PicoCTF 2018): an HTTP-by-hand problem, pretty straightforward.

### Forensics Challenges

1. [Puzzlingly Accountable](./PicoCTF2017/puzzlingly-accountable): simple extraction of PNG files from a PCAP problem with Wireshark and a little Python scripting

2. [Core](./PicoCTF2018/forensics/core) (PicoCTF 2018): analyze a core dump

### Miscellaneous Challenges

#### Scripting

1. [Script Me](./PicoCTF2018/misc/scriptme)(PicoCTF 2018): Fun with parentheses math

## By Language

(If not listed here, the challenge is probably written in C or Python.)

### Objective-C

1. [Turtles](./CSAW2018/turtles): binary exploitation problem using ROP, heap exploitation, and a format string vulnerability

### Esoteric Languages

1. [Much Ado About Hacking](./PicoCTF2017/much-ado) (PicoCTF 2017): Shakespeare Programming Language reversing problem

## By Architecture

(If not listed here, the challenge is a 32-bit or 64-bit Linux ELF binary.)

### ARM

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT CTF 2017) use of thumb mode during exploit development; crafting ARM shellcode

2. [Warm](./VolgaCTF2019/warm) (Volga CTF 2019): use of Ghidra to reverse a 32-bit ARM binary

### MIPS

1. [MIPS](./PicoCTF2017/MIPS) (PicoCTF 2017): reversing a MIPS binary containing branch-delay slots; usage of the SPIM simulator

## By Tool

(This section is mostly here to remind myself of various tricks to use when using tools.)

### GDB

1. [pwn5](./TAMUCTF2019/pwn5) (TAMUCTF 2019): `set follow-fork-mode parent` to step over a call to fork `execve`

2. [core](./PicoCTF2018/forensics/core) (PicoCTF 2018): `gdb [binary] [core]` to analyze a core dump
