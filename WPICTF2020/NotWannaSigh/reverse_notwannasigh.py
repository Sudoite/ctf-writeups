
# Reverse NotWannaSigh
from pwn import *

p = gdb.debug('/home/ctf/Documents/WPICTF2020/RE/WannaSigh/test/NotWannasigh',
	'''
	break main
	continue
	''')

p.interactive()

