# Assembly 4

This is a 550-point reversing problem from Pico CTF 2018.

### Problem Description

Can you find the flag using the following assembly [source](./comp.nasm)? WARNING: It is VERY long...

### Solution

The super-cheap solution is to just use `Ghidra` to lift the whole thing up to `C`. But this problem came out before Ghidra was open source, so I think I'll work with the assembly directly unless the hint tells me not to.

Okay, it's 1000 lines of code, and the hint says "don't reverse this directly." Time to decompile this. I could run the code in C and step through it with `gdb`, that seems legitimate. Actually first I'll just see if `Ghidra` has a feature that lets me decompile the raw assembly.

Second idea: I'll use `nasm` to compile the file into a binary and then just run it.

First, just for fun I wanted to see if I can just read this file with `Ghidra`. Indeed, `Ghidra` helps me out quite a bit. Here's `sub`:

```
int sub(char param_1,int param_2)

{
  int iVar1;
  int iVar2;

  iVar2 = (((int)param_1 + -0x30) - param_2) % 0x4e;
  iVar1 = iVar2 + 0x30;
  if (iVar2 < 0) {
    iVar1 = iVar2 + 0x7e;
  }
  return iVar1;
}
```

and `add`:

```
int add(char param_1,int param_2)

{
  return ((int)param_1 + -0x30 + param_2) % 0x4e + 0x30;
}
```

and `xor`:

```
int xor(char param_1,uint param_2)

{
  return (int)((int)param_1 - 0x30U ^ param_2 & 7) % 0x4e + 0x30;
}
```

Okay, there are some writes that happen at the end:

```
__buf = &local_4c;
do {
  write(1,__buf,1);
  __buf = __buf + 2;
} while (&local_20 != __buf);
__buf_00 = &local_4b;
do {
  write(1,__buf_00,1);
  __buf_00 = __buf_00 + 2;
} while (local_1f != __buf_00);
return 0;
```

So, it looks like characters are getting stored in these local variables, i.e. on the stack. And then the program just goes ahead and writes them off the stack: first all the even-numbered locals, and then all the odd-numbered locals. Looking at the first few assignments of the locals, we get:

```
local_14 = &param_1;
iVar1 = sub('x',0x1d);
iVar1 = (int)(char)iVar1 + 8;
iVar1 = (int)(char)((char)iVar1 + (char)(iVar1 / 0x4e) * -0x4e + '0') + -5;
local_4c = (char)iVar1 + (char)(iVar1 / 0x4e) * -0x4e + '0';
local_4a = 0x69;
iVar1 = sub('9',0x1c);
iVar1 = sub((char)iVar1 % 'N' + '0',0x38);
local_48 = (undefined)iVar1;
iVar1 = sub('s',0x20);
iVar1 = sub((char)iVar1,0x32);
iVar1 = (int)(char)iVar1 + -0x30;
local_46 = (char)iVar1 + (char)(iVar1 / 0x4e) * -0x4e + '0';
local_44 = 0x43;
iVar1 = sub('Q',0x1a);
iVar1 = (int)(char)iVar1 + -0x13;
local_42 = (char)iVar1 + (char)(iVar1 / 0x4e) * -0x4e + '0';
local_40 = 0x46;
local_3e = 0x7b;
```

`local_4a` is the second local to get printed, and it's "i"; `local_44` is the fifth, and it's a "C"; `local_40` and `local_3e` are the seventh and eighth and are "F{". So no doubt this is printing "picoCTF{". Great! `local_14`, the input parameter, appears to never get used, so it could be anything. That was helpful, time to move on to the second idea: compile and run this thing, probably in `gdb` so I can step through it.

To compile and link an ELF binary, I use:

```
nasm -f elf comp.nasm
ld -m elf_i386 comp.o -o comp -lc
```
I get one warning:
```
ld: warning: cannot find entry symbol _start; defaulting to 00000000080481c0
```

The resulting file, oddly, shows up as a file but I can't exeute it with `bash`. Let me try loading it with `gcc`:

```
nasm -f elf comp.nasm
gcc -m32 comp.o -o comp2
```

First let me just try running `comp2`. Doing so gives me:

`picoCTF{1_h0p3_y0u_c0mP1l3d_tH15_3205858729}`

Great! No need to use `gdb` at all.

### Comparison to Other Approaches

The other two write-ups on CTF Time indeed just go ahead and compile and run the assembly.
