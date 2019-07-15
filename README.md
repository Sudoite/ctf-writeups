# ctf-writeups

This is a repository of writeups for various CTF challenges. I am intentionally leaving in discussion about where I made mistakes or went down blind alleys, as such occasions can be great learning experiences, both for the person solving the challenge and potentially for the person reading the writeup. I hope they are informative and entertaining!

Here are some of my favorites:

1. [Turtles](./CSAW2018/turtles) (CSAW 2018): an entertaining Objective-C exploit that makes use of heap exploitation, format string attacks, and a buffer overflow / ROP chain.

2. [Leakless](./FireshellCTF2019/leakless) (Fireshell CTF 2019): a manual implementation of an attack that hijacks dynamic symbol resolution in Linux.

3. [Choose](./PicoCTF2017/final) (PicoCTF 2017 final challenge): I independently discovered a (possibly well-known) approach for bypassing a stack canary using characteristics of memory alignment for C structs in the GCC compiler.

4. [ECC2](./PicoCTF2017/ECC2) (PicoCTF 2017): this solution to an elliptic curve cryptography problem uses the Pohlig-Hellman algorithm.

5. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): an unintended solution to a ROP chain / reverse engineering problem involving a clever way to get a large value into the `rbx` register despite an apparent dearth of ROP gadgets containing `rbx`. That sets up a call to `read` and subsequent pivot to the `.bss` section to continue the ROP chain.

6. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): Overwrite a `libc` writable exit handler hook to loop back to the main function and set up a ROP chain. There were many creative solutions to this challenge.

7. [Flaskcards and Freedom](./PicoCTF2018/web/FlaskcardsAndFreedom) (PicoCTF2018): a web challenge to remote code execution from a Server-Side Template Injection (SSTI) vulnerability in a Flask site running on Jinja2. This problem was one of two challenges tied for the highest point value in this CTF. I showed a way to get a reverse shell and, after getting the flag during the competition, replicated three different approaches presented in other write-ups.

8. [Magic Padding Oracle](./PicoCTF2018/crypto/MagicPaddingOracle) (PicoCTF 2018): exploit a PKCS7 CBC padding oracle vulnerability to decrypt a server cookie and encrypt a forged cookie. To learn the technique, I implemented my own Python functions instead of using an online library. Despite this problem's intermediate-level challenge rating by the designers, it was the second-least-solved challenge.


## By category and technique

### Pwnable Challenges

#### Heap Exploitation

1. [Turtles](./CSAW2018/turtles): squeezing as many fake smallbins as possible into a small space on the heap; writing a ROP chain that will work despite part of it getting copied from the stack to the heap, potentially corrupting the heap.

2. [Chat Logger](./PicoCTF2017/chat-logger) (PicoCTF 2017): abuse a bug in the program to change the maximum length of a message, then edit a short message to overwrite a subsequent chunk in the heap.

3. [Enter the Matrix](./PicoCTF2017/matrix) (PicoCTF 2017): exploit a bug in how rows and columns of a matrix are accessed to write beyond a chunk's boundary.

4. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): get `calloc` to return a null pointer by allocating too much memory, and exploit the null pointer.

5. [Heap Golf](./SwampCTF2019/heapgolf) (Swamp CTF 2019): a simple heap problem illustrating how fastbins work.


###### Use After Free

1. [Aggregator](./PicoCTF2017/aggregator) (PicoCTF 2017): overwriting the Global Offset Table using Use After Free.

2. [Contact Helper](./PicoCTF2017/contact-helper) (PicoCTF 2017): an unintended solution to a heap exploitation problem with a UAF vulnerability.

#### ROP Chain

1. [Turtles](./CSAW2018/turtles) (CSAW2018): this solution uses One Gadget.

2. [OTP-Server](./FacebookCTF2019) (FaceBook CTF 2019): I write a ROP chain one byte at a time using random bytes with values I can test.

3. [Overfloat](./FacebookCTF2019) (FaceBook CTF 2019): a ROP chain that works with 32-bit floats.

4. [Deeper into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): this ROP chain is similar to that in [Overfloat](./FacebookCTF2019/overfloat), but the exploit also bypasses full RELRO protection.

4. [Leakless](./FireshellCTF2019/leakless) (Fireshell CTF 2019): I attack dynamic symbol lookup in ELF binaries, with a full explanation of the technique. One of my favorite write-ups.

5. [pwn5](./TAMUCTF2019/pwn5) (TAMUCTF 2019): a simple intro-level ROP problem.

6. [Defcon Quals Speedrun 2](./DefConQuals2019/speedrun2/README.md) (DEF CON Quals 2019): a ROP problem without a `libc` version provided.

7. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): an unintended solution involving a clever way to move a large value into `rbx` while setting up a pivot to the `.bss` section with a call to `read`.

8. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): I overwrite a `libc` writable hook for an exit handler to loop back to the main function and set up a ROP chain.

##### Statically-linked binary

1. [Defcon Quals Speedrun 1](./DefConQuals2019/speedrun1) (DEF CON Quals 2019): a simple ROP problem.

2. [ropberry](./INSHack2019/pwn/ropberry): a 64-bit ROP chain.

3. [Onewrite](./Insomnihack2019/onewrite) (Insomnihack 2019): a 64-bit ROP chain and statically-linked binary, but definitely non-trivial!

#### Format Strings

1. [Turtles](./CSAW2018/turtles) (CSAW2018): a straightforward information leak.

2. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): I bypass a canary using a format string leak.

3. [Flagsay-2](./PicoCTF2017/flagsay-2) (PicoCTF 2017): a straightforward overwrite of the Global Offset Table.


#### Shellcode

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): I used 32-bit ARM shellcode to solve this challenge.

2. [Choose](./PicoCTF2017/final) (PicoCTF 2017): 32-bit Linux `x86` shellcode to execute `execve`, split into 11-byte sections and using relative jumps to string the shellcode together.

3. [pwn3](./TAMUCTF2019/pwn3) (TAMUCTF 2019): simple Linux `x86` shellcode, executed on the stack.

4. [gimmeyourshell](./INSHack2019/pwn/gimmeyourshell) (INSHack 2019): Linux `x86-64` shellcode, executed on the stack.

#### Bypassing stack canaries

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT 2017): an example of bypassing a canary using a format string leak.

2. [Choose](./PicoCTF2017/final) (PicoCTF 2017): an example of bypassing a canary using "holes" in C structs generated by the GCC compiler for alignment reasons.

3. [quicksort](./StarCTF2019/quicksort) (`*CTF2019`): A vulnerability in the C code allows function pointers to be overwritten -- but whatever then gets written is subsequently treated as a list of integers and sorted in place, leading to a creative specification of the `/bin/sh` string in order to execute `system("/bin/sh")`.

#### Bypassing full RELRO

1. [Deeper Into the Matrix](./PicoCTF2017/matrix-deeper) (PicoCTF 2017): an example of bypassing full RELRO protection by writing to a writable hook to `malloc`, `calloc`, or `free` in `libc`.


#### Simple Buffer Overflow

1. [pwn1](./TAMUCTF2019/pwn1) (TAMUCTF 2019): a trivial, speedrun-type buffer overflow problem.

2. [big_boi](./CSAW2018/bigboi) (CSAW CTF 2018): a very simple problem involving overwriting an integer with another.

3. [pwn2](./TAMUCTF2019/pwn2) (TAMUCTF 2019): return to a function to print the flag.

4. [get-it](./CSAW2018/get_it) (CSAW CTF 2018): a partial overwrite of the return address to print the flag.

5. [warm](./VolgaCTF2019/warm) (VolgaCTF Quals 2019): this exploit overwrites a file name to open an arbitrary file on the server.


### Cryptography Challenges

1. [ECC2](./PicoCTF2017/ECC2) (PicoCTF 2017): an elliptic curve cryptography problem, solved with the Pohlig-Hellman algorithm.

2. [Encrypted Shell](./PicoCTF2017/encrypted-shell) (PicoCTF 2017): an application of Pollard's kangaroo algorithm to solve the discrete log problem to get a private key for the Diffie-Hellman public key exchange protocol. (Not an original solution.)

3. [Blind](./VolgaCTF2019/blind) (Volga CTF Quals 2019): an implementation of an RSA blinding attack.

4. [eleCTRic](./PicoCTF2018/crypto/eleCTRic) (PicoCTF 2018): an attack on an improperly-implemented version of AES using counter mode.

5. [SpyFi](./PicoCTF2018/crypto/SpyFi) (PicoCTF 2018): a chosen plaintext attack on AES using Electronic Code Book (ECB) mode.

6. [Smallsign](./PicoCTF2017/smallsign) (PicoCTF 2017): forge an RSA signature using a chosen plaintext attack by taking advantage of smooth numbers.

7. [Magic Padding Oracle](./PicoCTF2018/crypto/MagicPaddingOracle) (PicoCTF 2018): exploit a PKCS7 CBC padding oracle vulnerability to decrypt a server cookie and encrypt a forged cookie. To learn the technique, I implemented my own Python functions instead of using an online library.

#### RSA

1. [Super Safe RSA 2](./PicoCTF2018/crypto/SuperSafeRSA2) (PicoCTF 2018): an application of Weiner's attack in the case of small `d`.

### Reverse Engineering Challenges

1. [MIPS](./PicoCTF2017/MIPS) (PicoCTF 2017): reversing a MIPS binary containing branch-delay slots; usage of the SPIM simulator

2. [Forest](./PicoCTF2017/forest) (PicoCTF 2017): a straightforward problem reversing a binary that looks up symbols in a tree to generate a message.

3. [Much Ado About Hacking](./PicoCTF2017/much-ado) (PicoCTF 2017): decompiling a program written in the Shakespeare Programming Language.

4. [Warm](./VolgaCTF2019/warm) (VolgaCTF Quals 2019): this is a pwnable challenge, but it shows how easy it is to use Ghidra to reverse an ARM executable.

5. [Silk Road I](./ASISCTF2019/silkroad) (ASIS CTF Quals 2019): this pwnable challenge requires reverse-engineering some code and satisfying a set of constraints to compute a secret key, in order to proceed to the actual vulnerable section of the code.

6. [Keygenme-1](./PicoCTF2018/RE/keygenme-1) (PicoCTF 2018): reverse-engineer a program to validate product keys. This one wasn't too tricky.

7. [Lithp](./AngstromCTF2019/lithp) (AngstromCTF 2019): easy Lisp reversing problem.

### Web Challenges

1. [A Kaley Ceilidh](./PicoCTF2017/kaley-ceilidh) (PicoCTF 2017): a blind NoSQL injection attack on a server running MongoDB and NodeJS. The problem also covers Http requests in Python. (Solved with hints from other sources.)

2. [Artisinal Hand-Crafted HTTP3](./PicoCTF2018/web/ArtisinalHTTP3) (PicoCTF 2018): an HTTP-by-hand problem, pretty straightforward.

3. [Flaskcards](./PicoCTF2018/web/Flaskcards) (PicoCTF 2018): a simple Server-Side Template Injection (SSTI) problem involving a Flask website running on Jinja2.

4. [Flaskcards Skeleton Key](./PicoCTF2018/web/FlaskcardsSkeletonKey) (PicoCTF2018): forge an admin cookie given the secret key to decrypt Flask session cookies.

5. [Flackcards and Freedom](./PicoCTF2018/web/FlaskcardsAndFreedom) (PicoCTF2018): obtain remote code execution from a Server-Side Template Injection (SSTI) vulnerability in a Flask site running on Jinja2. I showed a way to get a reverse shell and, after solving it, replicated three different approaches presented in other write-ups.

6. [A Simple Question](./PicoCTF2018/web/ASimpleQuestion) (PicoCTF2018): Python implementation of an automated blind SQL injection exploit. (A solution with `SQLMap` is also presented, but I learned more from writing my own code to solve the challenge.)


### Forensics Challenges

1. [Puzzlingly Accountable](./PicoCTF2017/puzzlingly-accountable) (PicoCTF 2017): a simple extraction of PNG files from a PCAP problem with Wireshark and a little Python scripting.

2. [Core](./PicoCTF2018/forensics/core) (PicoCTF 2018): analyze a core dump.

3. [Ext Super Magic](./PicoCTF2018/forensics/ExtSuperMagic) (PicoCTF 2018): extract files from a corrupted `ext2` file system.

### General Skills

#### Scripting

1. [Script Me](./PicoCTF2018/misc/scriptme) (PicoCTF 2018): fun with parentheses math.

#### Random Number Generators

1. [Roulette](./PicoCTF2018/misc/roulette) (PicoCTF 2018): exploit a program with a poor random seed and unsafe casting of an unsigned long to a signed long.

## By Language

(If not listed here, the challenge is probably written in C or Python.)

### Objective-C

1. [Turtles](./CSAW2018/turtles): a binary exploitation problem using ROP, heap exploitation, and a format string vulnerability.

### Lisp

1. [Lithp](./AngstromCTF2019/lithp) (AngstromCTF 2019): easy Lisp reversing problem.

### Esoteric Languages

1. [Much Ado About Hacking](./PicoCTF2017/much-ado) (PicoCTF 2017): a Shakespeare Programming Language reversing problem.

## By Architecture

(If not listed here, the challenge is a 32-bit or 64-bit Linux ELF binary.)

### ARM

1. [Terminator Canary](./HackIT2017_pwn200) (HackIT CTF 2017) a use of thumb mode during exploit development, and an example of crafting ARM shellcode.

2. [Warm](./VolgaCTF2019/warm) (Volga CTF 2019): a use of Ghidra to reverse a 32-bit ARM binary.

### MIPS

1. [MIPS](./PicoCTF2017/MIPS) (PicoCTF 2017): an example of reversing a MIPS binary containing branch-delay slots; I also used the SPIM simulator.

## By Tool

(This section is mostly here to remind myself of various tricks to use when using tools.)

### GDB

1. [pwn5](./TAMUCTF2019/pwn5) (TAMUCTF 2019): I used `set follow-fork-mode parent` to step over a call to fork `execve`.

2. [core](./PicoCTF2018/forensics/core) (PicoCTF 2018): I used `gdb [binary] [core]` to analyze a core dump.
