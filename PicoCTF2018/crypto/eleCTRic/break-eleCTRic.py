### break-eleCTRic.py

from pwn import *
from time import sleep
import binascii
import base64

# Hint from teammate: https://cryptopals.com/sets/3/challenges/19

# Helper functions to convert 64-bit addresses to strings and vice versa
pck = lambda x: struct.pack('Q', x)
unpck = lambda x: struct.unpack('Q', x)

local = False
if local:
	DELAY = 0.1
else:
	DELAY = 0.35

def spawn_process(local=True):
	if local:
		p=process('python2 ./eleCTRic.py', shell=True)
	else:
		p = remote('2018shell2.picoctf.com', 42185)
	return p

def encrypt_new_file(filename, contents):
	p.send("n\n")
	time.sleep(0.5)
	p.recvuntil("? ")
	p.send(filename+"\n")
	time.sleep(0.5)
	p.recvuntil("Data? ")
	p.send(contents+"\n")
	p.recvuntil("\n")
	ciphertext = p.recvuntil("\n")
	p.recvuntil("choose: ")
	return ciphertext[0:len(ciphertext)-1]

def string_to_hex(string):
	return binascii.hexlify(string)

def xor_two_hex_strings(str1, str2):
	minlength = min(len(str1),len(str2))
	result = ''
	if minlength % 2 != 0:
		log.info("In xor_two_hex_strings: odd length detected. Exiting.")
		return('')
	for i in range(0,minlength/2):
		byte1 = ord(binascii.unhexlify(str1[i*2:i*2+2]))
		byte2 = ord(binascii.unhexlify(str2[i*2:i*2+2]))
		result += binascii.hexlify(chr(byte1 ^ byte2))
	return result

def get_encrypted_filename(code):
	return string_to_hex(base64.b64decode(code))

p = spawn_process(local=local)

flag_filename = "flag_2cd5bfb715299d64a0e1.txt"
fake_filenam1 = "AAAAAAAABBBBBBBBCCCCCCCCD"
fake_filenam2 = "EEEEEEEEFFFFFFFFGGGGGGGGH"

cipher1 = encrypt_new_file(filename=fake_filenam1,contents="Anything")
cipher2 = encrypt_new_file(filename=fake_filenam2,contents="Anything")
log.info("cipher1 = " + cipher1)
cipher1_hex = get_encrypted_filename(cipher1)
cipher2_hex = get_encrypted_filename(cipher2)
plain1_hex = string_to_hex(fake_filenam1+".txt")
plain2_hex = string_to_hex(fake_filenam2+".txt")
log.info("cipher1_hex = " + cipher1_hex)
#log.info("cipher2_hex = " + cipher2_hex)
log.info("plain1_hex = " + plain1_hex)
#log.info("plain2_hex = " + plain2_hex)

key_plus_nonce_1 = xor_two_hex_strings(cipher1_hex, plain1_hex)
key_plus_nonce_2 = xor_two_hex_strings(cipher2_hex, plain2_hex)
#log.info("cipher1_hex xor plain1_hex = " + key_plus_nonce_1)
#log.info("cipher2_hex xor plain2_hex = " + key_plus_nonce_2)
# Yes, they're the same as expected. Great. That means I've recovered the key (plus the CTR).


# Let me try to get back the original cipher that I got for the first filename.
filename1 = xor_two_hex_strings(string_to_hex(fake_filenam1+".txt"),key_plus_nonce_1)
#log.info("I think filename1 encoded should be" + base64.b64encode(binascii.unhexlify(filename1)))
#log.info("And its actual value is            " + cipher1)
# That's correct.

# The flag filename keeps changing each time I run the application. So I have to get its
# value programmatically.
time.sleep(0.5)
p.send("i\n")
p.recvuntil("Files:")
got_flag = False
while not got_flag:
	time.sleep(0.2)
	p.recvuntil("\n  ")
	flag_filename = p.recvuntil(".txt")
	#log.info(" Candidate filename = " + flag_filename)
	if flag_filename[0:4] == "flag":
		got_flag = True
		break
log.info("flag_filename = " + flag_filename)


flag_enciphered = xor_two_hex_strings(string_to_hex(flag_filename),key_plus_nonce_1)
log.info("enciphered flag unhexlified and encoded = " + base64.b64encode(binascii.unhexlify(flag_enciphered)))

encoded_flag = base64.b64encode(binascii.unhexlify(flag_enciphered))

# Now submit the encoded flag
p.recvuntil("choose: ")
p.send("e\n")
p.recvuntil("code? ")
p.send(encoded_flag+"\n")
p.interactive()
