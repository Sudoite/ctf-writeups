### break-spify.py

from pwn import *
from time import sleep
from math import floor
# Helper functions to convert 64-bit addresses to strings and vice versa
pck = lambda x: struct.pack('Q', x)
unpck = lambda x: struct.unpack('Q', x)

local = False
if local:
	DELAY = 0.1
else:
	DELAY = 0.35
# Helper function, adds null bytes to the end of a hex address so we can pack it
def append_nulls(str):
	n = len(str)
	for i in xrange(8 - n):
		str += '\x00'
	return str

def spawn_process(local=True):
	if local:
		p=process('python2 ./spy_terminal_no_flag.py', shell=True)
	else:
		p = remote('2018shell2.picoctf.com', 33893)
	return p

def get_block(message, bn):
	return message[bn*32:bn*32+32]

def print_blocks(message):
	n_complete_blocks = int(floor(len(message)/32.0))
	print("n_complete_blocks = " + str(n_complete_blocks))
	for i in range(0,n_complete_blocks):
		print("m[" + str(i) + "] = " + get_block(message,i))

def print_two_blocks(message, b1, b2):
	print("printing two blocks: ")
	print("    m[" + str(b1) + "] = " + get_block(message,b1))
	print("    m[" + str(b2) + "] = " + get_block(message,b2))

def blocks_are_equal(message, b1, b2):
	return(get_block(message,b1) == get_block(message,b2))

def check_letter(decrypted_flag, letter, local=True):
	p=spawn_process(local)
	p.recvuntil("!")
	letter = letter
	payload = 'A'*(43-(1+len(decrypted_flag)))+'ifying code is: ' + decrypted_flag + letter + 'A'*(64-len(decrypted_flag))
	print("payload = " + payload)
	p.sendline(payload)
	p.recvuntil(": ")
	m2 = p.recvuntil('\n')
	p.close()
	time.sleep(DELAY) # will have to be longer for server
	if(blocks_are_equal(m2, 6, 12)): # will need to update to 
		print("The correct letter is " + letter + ".")
		return True
	else:
		return False


flag = ''
# Run this until I get an end bracket, add known characters to the 
# flag string above if the code gets interrupted
done = False
while not(done):
	for i in range(32,127,1):
		print("checking letter..." + chr(i))
		print("flag = " + flag)
		if check_letter(flag, chr(i), local):
			print("   Got letter: " + chr(i))
			flag += chr(i)
			if chr(i) == '}':
				done = True
			break
print("flag = " + flag)