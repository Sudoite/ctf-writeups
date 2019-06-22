# ctf-writeups

This is a repository of writeups for various CTF challenges. I am intentionally leaving in discussion about where I made mistakes or went down blind alleys, as such occasions can be great learning experiences, both for the person solving the challenge and potentially for the person reading the writeup. I hope they are informative and entertaining! To read a write-up, just click through to the `.md` file with the same name as the challenge.

Here are some of my favorites:

1. [Turtles](./CSAW2018/turtles/turtles.md) from CSAW 2018 -- an entertaining Objective-C exploit that makes use of heap exploitation, format string attacks, and a buffer overflow / ROP chain

2. [Leakless](./FireshellCTF2019/leakless/leakless.md) from Fireshell CTF 2019 -- a manual implementation of an attack that hijacks dynamic symbol resolution in Linux

3. [Choose](./PicoCTF2017/final/Final.md): the final challenge for PicoCTF2017, in which I independently discovered an approach for bypassing a stack canary using characteristics of memory alignment for C structs in the GCC compiler

4. [ECC2](./PicoCTF2017/ECC2/ECC2.md): an elliptic curve cryptography problem from PicoCTF 2017

## By category and technique

### Pwnable Challenges

#### Heap Exploitation

1. [Turtles](./CSAW2018/README.md): Squeezing as many fake smallbins as possible into a small space on the heap; writing a ROP chain that will work despite part of it getting copied from the stack to the heap, potentially corrupting the heap

2. [Chat Logger](./PicoCTF2017/chat-logger/README.md) (PicoCTF 2017): abuse a bug in the program to change the maximum length of a message, then edit a short message to overwrite a subsequent chunk in the heap

3. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper/README.md): get `calloc` to return a null pointer by allocating too much memory, and exploit the null pointer

4. [Enter the Matrix](./PicoCTF2017/matrix/README.md): Exploit a bug in how rows and columns of a matrix are accessed to write beyond a chunk's boundary

###### Use After Free

1. [Aggregator](./PicoCTF2017/Aggregator/README.md) (PicoCTF 2017): Overwriting the Global Offset Table using Use After Free

2. [Contact Helper](./PicoCTF2017/contact-helper/README.md) (PicoCTF 2017): unintended solution to a heap exploitation problem with a UAF vulnerability.

#### ROP Chain

1. [Turtles](./CSAW2018/README.md) (CSAW2018): use of One Gadget

2. [OTP-Server](./FacebookCTF2019/README.md) (FaceBook CTF 2019): write a ROP chain one byte at a time using random bytes with values I can test

3. [Overfloat](./FacebookCTF2019/README.md) (FaceBook CTF 2019): ROP chain that works with 32-bit floats

4. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper/README.md) (PicoCTF 2017): same idea as [Overfloat](./FacebookCTF2019/README.md), but with full RELRO protection

4. [Leakless](./FireshellCTF2019/README.md) (Fireshell CTF 2019): attacking dynamic symbol lookup in ELF binaries, with a full explanation of the technique

5. [pwn5](./TAMUCTF2019/pwn5/README.md) (TAMUCTF 2019): simple intro-level ROP problem

6. [Defcon Quals Speedrun 1](./DefConQuals2019/speedrun1/README.md) (DEF CON Quals 2019): simple ROP problem

7. [Defcon Quals Speedrun 2](./DefConQuals2019/speedrun2/README.md) (DEF CON Quals 2019): ROP problem without a `libc` version provided


#### Format Strings

1. [Turtles](./CSAW2018/README.md) (CSAW2018): straightforward info leak

2. [Terminator Canary](./HackIT2017_pwn200/README.md) (HackIT 2017): bypass a canary using a format string leak

3. [Flagsay-2](./PicoCTF2017/flagsay-2/README.md) (PicoCTF 2017): straightforward overwrite of the Global Offset Table


#### Shellcode

1. [Terminator Canary](./HackIT2017_pwn200/README.md): 32-bit ARM shellcode

2. [Choose](./PicoCTF2017/final/README.md): 32-bit Linux `x86` shellcode to execute `execve`, split into 11-byte sections and using relative jumps to string the shellcode together

3. [pwn3](./TAMUCTF2019/pwn3/README.md) (TAMUCTF 2019): simple 32-bit Linux `x86` shellcode, executed on the stack


#### Bypassing stack canaries

1. [Terminator Canary](./HackIT2017_pwn200/README.md): bypass a canary using a format string leak

2. [Choose](./PicoCTF2017/final/README.md): bypass a canary using "holes" in C structs generated by the GCC compiler for alignment reasons


#### Bypassing full RELRO

1. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper/README.md) (PicoCTF 2017): bypass full RELRO protection by writing to a writable hook to `malloc`, `calloc`, or `free` in `libc`


#### Simple Buffer Overflow

1. [pwn1](./TAMUCTF2019/pwn1/README.md) (TAMUCTF 2019): trivial, speedrun-type problem

2. [pwn2](./TAMUCTF2019/pwn2/README.md) (TAMUCTF 2019): return to a function to print the flag


### Cryptography Challenges

1. [ECC2](./PicoCTF2017/ECC2/README.md) (PicoCTF 2017): elliptic curve cryptography problem, solved with the Pohlig-Hellman algorithm

2. [Encrypted Shell](./PicoCTF2017/encrypted-shell/README.md) (PicoCTF 2017): Application of Pollard's kangaroo algorithm to solve the discrete log problem to get a private key for the Diffie-Hellman public key exchange protocol. (Not an original solution.)

### Reverse Engineering Challenges

1. [MIPS](./PicoCTF2017/MIPS/README.md) (PicoCTF 2017): reversing a MIPS binary containing branch-delay slots; usage of the SPIM simulator

2. [Forest](./PicoCTF2017/forest/README.md) (PicoCTF 2017): Straightforward problem reversing a binary that looks up symbols in a tree to generate a message.

3. [Much Ado About Hacking](./PicoCTF2017/much-ado/README.md) (PicoCTF 2017): decompiling a program written in the Shakespeare Programming Language

### Web Challenges

1. [A Kaley Ceilidh](./PicoCTF2017/kaley-ceilidh/README.md) (PicoCTF 2017): A blind NoSQL injection attack on a server running MongoDB and NodeJS. Also covers Http requests in Python. (Solved with hints from other sources)

### Forensics Challenges

1. [Puzzlingly Accountable](./PicoCTF2017/puzzlingly-accountable/README.md): simple extraction of PNG files from a PCAP problem with Wireshark and a little Python scripting

## By Language

(If not listed here, the challenge is probably written in C or Python.)

### Objective-C

1. [Turtles](./CSAW2018/README.md): binary exploitation problem using ROP, heap exploitation, and a format string vulnerability

### Esoteric Languages

1. [Much Ado About Hacking](./PicoCTF2017/much-ado/README.md) (PicoCTF 2017): Shakespeare Programming Language reversing problem

## By Architecture

(If not listed here, the challenge is a 32-bit or 64-bit Linux ELF binary.)

### ARM

1. [Terminator Canary](./HackIT2017_pwn200/README.md) -- use of thumb mode during exploit development; crafting ARM shellcode

### MIPS

1. [MIPS](./PicoCTF2017/MIPS/README.md) (PicoCTF 2017): reversing a MIPS binary containing branch-delay slots; usage of the SPIM simulator

## By Tool

(This section is mostly here to remind myself of various tricks to use when using tools.)

### GDB

[pwn5](./TAMUCTF2019/pwn5/README.md) (TAMUCTF 2019): `set follow-fork-mode parent` to step over a call to fork `execve`
