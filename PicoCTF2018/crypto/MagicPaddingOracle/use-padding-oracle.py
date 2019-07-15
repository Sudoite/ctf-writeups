
## break-padding-oracle.py
## by Sudoite

from pwn import *
from math import floor
import binascii
import base64
import cPickle

local = False
BSIZE = 16 # block size. The code would be more elegant if I were to actually use this...

def spawn_process(local=True):
	if local:
		p=process('python2 ./pkcs7.py', shell=True)
	else:
		p = remote('2018shell2.picoctf.com', 6246)
	return p


########     D  E  C  R  Y  P  T  I  O  N     F  U  N  C  T  I  O  N  S     #########

def string_to_hex(string):
	return binascii.hexlify(string)

def hex_to_string(hex_string):
	return binascii.unhexlify(hex_string)

def xor_two_hex_strings(str1, str2):
	minlength = min(len(str1),len(str2))
	result = ''
	if minlength % 2 != 0:
		print("In xor_two_hex_strings: odd length detected. Exiting.")
		return('')
	for i in range(0,minlength/2):
		byte1 = ord(binascii.unhexlify(str1[i*2:i*2+2]))
		byte2 = ord(binascii.unhexlify(str2[i*2:i*2+2]))
		result += binascii.hexlify(chr(byte1 ^ byte2))
	return result

def hex_a_number(n):
	result = hex(n)[2:len(hex(n))]
	if len(result) == 1:
		result = '0'+result # prepending anything less than 0x10 with a zero
	return result

# The offset is the byte number, not the char number in the string
def get_candidate_byte_from_ctext(ctext_block, offset):
	insertion_point = offset*2

	return ctext_block[insertion_point:insertion_point+2]

def generate_replacement_ciphertext_byte(ctext_block, guess, padding, guess_offset):
	# 1. Get the candidate byte from the ctext_block
	candidate_byte = get_candidate_byte_from_ctext(ctext_block,offset=guess_offset)
	# This last approach is used for padding guess bytes in the last block
	# 2. Get the padding byte
	padding_byte = hex_a_number(padding)
	# 3. xor the guess with the padding byte
	guess_hexed = hex_a_number(guess)
	# 4. xor the candidate byte with the (guess xor the padding byte)
	replacement_ciphertext_byte = xor_two_hex_strings(xor_two_hex_strings(padding_byte, candidate_byte),guess_hexed)
	# 5. return the guess byte
	print("guess_hexed = " + guess_hexed)
	print("replacement ciphertext byte = " + replacement_ciphertext_byte)
	return replacement_ciphertext_byte

# Adds to the end of the ciphertext block the bytes that will produce the desired 
# padding in the plaintext
def generate_msg_padding_byte(ctext_block, msg_block, msg_offset, padding):
	# 1. Get the candidate byte from the ctext_block
	# 2. Get the padding byte
	# 3. Get the message byte
	# 4. xor the candidate byte with the message byte (gives us 0x00)
	candidate_byte = get_candidate_byte_from_ctext(ctext_block,offset=16-padding+1+msg_offset)
	padding_byte = hex_a_number(padding)
	msg_byte = msg_block[msg_offset*2:msg_offset*2+2]
	msg_padding_byte = xor_two_hex_strings(xor_two_hex_strings(padding_byte, candidate_byte),msg_byte)
	return msg_padding_byte

def replace_ciphertext_block_with_ciphertext_guess(ctext_block, msg_block, padding, guess, guess_offset=None):
	# 1. result += ctext before the guess
	if guess_offset is None:
		guess_offset = 16-padding
	result = ctext_block[0:guess_offset*2]
	# 2. result += Get the candidate byte xor the guess xor the padding byte number
	result += generate_replacement_ciphertext_byte(ctext_block, guess, padding, guess_offset)
	for i in range(len(msg_block)/2):
		result += generate_msg_padding_byte(ctext_block, msg_block, i, padding)
	return result


# Usable for ctext and msg
def get_text_block(text, block_number):
	#print("text block " + str(block_number) + " = " + text[block_number*32:block_number*32+32])
	return text[block_number*32:block_number*32+32]

def get_text_blocks(text):
	result = []
	n_blocks = len(text)/32
	for i in range(n_blocks):
		result.append(text[i*32:i*32+32])
	return result

# Send a guess and see if it was right
def guess_is_right(guessed_ciphertext):
	p = spawn_process(local=local)
	p.readuntil("What is your cookie?")
	p.send(guessed_ciphertext+"\n")
	p.readline()
	response = p.readline()
	print(response)
	if response[0:15] == "invalid padding":
		p.close()
		return False
	else:
		# If the guess is right, then actually the decoder breaks and the application throws 
		# an error. But I don't care about that. I just close and return.
		#
		# Example error message:
		#File "/problems/magic-padding-oracle_2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pkcs7.py", line 47, in <module>
		#    d=json.loads(unpad(cookie2decoded))
		#File "/usr/lib/python2.7/json/__init__.py", line 339, in loads
		#	return _default_decoder.decode(s)
		#File "/usr/lib/python2.7/json/decoder.py", line 364, in decode
		#	obj, end = self.raw_decode(s, idx=_w(s, 0).end())
		#File "/usr/lib/python2.7/json/decoder.py", line 380, in raw_decode
		#		obj, end = self.scan_once(s, idx)
		#ValueError: Unterminated string starting at: line 1 column 14 (char 13)
		#p.interactive()
		p.close()
		return True

# To send a guess (assume I am not looping and know the guess byte, kind of inefficient here but fine),
# given the ctext, the last block of the message, the index of the ctext block I'm interested
# in modifying, and the guess:
# 1. Append previous ctext blocks, if any (none at the beginning)
# 1.5. Get the current ctext block using its index
# 2. Get the candidate last ciphertext block using
#    replace_ciphertext_block_with_ciphertext_guess(ctext_block, msg_block, padding, guess)
#    and append it
# 3. Get the next next ctext block and append it
# 4. Send the request to the server and evaluate the response to see if the server detected padding
# 5. Return True (guess was right) or False (guess was wrong)
def make_a_guess(ctext, ctext_block_index, msg_block, padding, guess, guess_offset=None):
	input_for_server = ctext[0:ctext_block_index*32]
	current_ctext = get_text_block(ctext, ctext_block_index)
	print("in make_a_guess: current_ctext = " + current_ctext)
	candidate_block = replace_ciphertext_block_with_ciphertext_guess(ctext_block=current_ctext,
		msg_block=msg_block,
		padding=padding,
		guess=guess,
		guess_offset=guess_offset)
	print("candidate_block = " + candidate_block)
	input_for_server += candidate_block
	input_for_server += get_text_block(ctext, ctext_block_index+1)
	print("input for server = " + input_for_server)
	print("block number " + str(ctext_block_index))
	print("padding = " + str(padding))
	print("msg_block = " + msg_block)
	result = guess_is_right(input_for_server)
	print(result)
	return result


# Now I need to guess a byte and return the decrypted byte
def guess_byte(ctext, ctext_block_index, msg_block, padding):
	# This first range seems to be more likely given 
	# whatever the server key is, so I'm optimizing a little here
	# Update: moved to second for loop for last block
	print("In guess_byte: ctext = " + ctext)
	for guess in range(54,256):
		print("guess = " + str(guess))
		correct = make_a_guess(ctext, ctext_block_index, msg_block, padding, guess)
		if correct:
			print("Guessed right! Guess was " + str(guess))
			return guess
	for guess in range(0,54):
		print("guess = " + str(guess))
		correct = make_a_guess(ctext, ctext_block_index, msg_block, padding, guess)
		if correct:
			print("Guessed right! Guess was " + str(guess))
			return guess			
	print("No guess worked! Something is wrong...")
	return None

# I need a function that will return all possible values for a byte. Necessary 
# for the block that actually contains padding.
def get_all_valid_guesses_for_padding_byte(ctext, ctext_block_index, msg_block, padding):
	print("In get_all_valid_guesses_for_byte: ctext = " + ctext)
	correct_guesses = []
	for guess in range(1,17):
		print("guess = " + str(guess))
		correct = make_a_guess(ctext, ctext_block_index, msg_block, padding, guess)
		if correct:
			print("Guessed right! Guess was " + str(guess))
			correct_guesses.append(guess)
			print("Correct guesses so far: " + str(correct_guesses))
	return correct_guesses

def get_all_valid_guesses_for_plaintext_byte(ctext, ctext_block_index, msg_block, padding):
	print("In get_all_valid_guesses_for_byte: ctext = " + ctext)
	correct_guesses = []
	for guess in range(0,256):
		print("guess = " + str(guess))
		correct = make_a_guess(ctext, ctext_block_index, msg_block, padding, guess)
		if correct:
			print("Guessed right! Guess was " + str(guess))
			correct_guesses.append(guess)
			print("Correct guesses so far: " + str(correct_guesses))
	return correct_guesses

# Now I want to get an entire message block
def guess_message_block(ctext, ctext_block_index):
	msg_block=""
	for padding in range(1,17):
		successful_guess = guess_byte(ctext, ctext_block_index, msg_block, padding)
		if successful_guess:
			print("successful_guess = " + str(successful_guess))
			msg_block = hex_a_number(successful_guess) + msg_block  # working forwards from the end of the block
			print("msg_block = " + msg_block)
		else:
			print("In guess_message_block: wasn't able to guess any byte!")
	print("Just decrypted a message block: " + msg_block)
	return msg_block

# In case I lose my Internet connection partway through an attack, move some intermediate results to disk.
def save_message_block(content, filename):
	with open(filename, "wb") as output_file:
		cPickle.dump(content, output_file)
	return

# In case I lose my Internet connection partway through an attack.
def load_message_block(filename):
	with open(filename, "rb") as input_file:
		recovered_msg_block = cPickle.load(input_file)
	return recovered_msg_block

# Strategy: if 1 is the only valid guess, the padding byte is 1.
# Otherwise, if there are two valid guesses, the padding byte is probably the one that's not 1
#    but it still could be 1.
#    In this situation, set the number of padding bytes equal to the case for the padding 
#       byte not being one, and get all valid guesses for the next byte after the padding.
#       If I return no valid guesses, I know that the padding byte is actually 1.
#       Otherwise, I know the padding byte is the one that's not 1.
def determine_message_padding(ctext):
	n_blocks = len(ctext)/32
	ctext_block_index = n_blocks - 2 # minus 1 for the IV and 1 for zero-order indexing
	valid_guesses_for_padding_byte = get_all_valid_guesses_for_padding_byte(ctext, ctext_block_index, msg_block="", padding=1)
	print("all valid guesses: " + str(valid_guesses_for_padding_byte))
	#valid_guesses_for_padding_byte = [1, 13]
	n_valid_guesses = len(valid_guesses_for_padding_byte)
	print("n_valid_guesses = " + str(n_valid_guesses))
	if n_valid_guesses !=2:
		padding = 0x01
	else:
		candidate_padding = valid_guesses_for_padding_byte[1]
		if candidate_padding == 16:
			padding = 16
		else:
			valid_plaintext_bytes = get_all_valid_guesses_for_plaintext_byte(ctext, ctext_block_index=4, msg_block=binascii.hexlify(chr(candidate_padding)*candidate_padding), padding=candidate_padding+1)
			print("valid_plaintext_bytes = " + str(valid_plaintext_bytes))
			n_valid_plaintext_bytes = len(valid_plaintext_bytes)
			if n_valid_plaintext_bytes != 1:
				padding = valid_guesses_for_padding_byte[0]
			else:
				padding = candidate_padding
	return padding


# And now I want to determine the last message block with a single function
def guess_last_message_block(ctext):
	n_blocks = len(ctext)/32
	ctext_block_index = n_blocks - 2 # minus 1 for the IV and 1 for zero-order indexing
	plaintext_padding = determine_message_padding(ctext)
	# Make this print statement loud
	for i in range(50):
		print("In guess_last_message_block: determined that plaintext padding = " + str(plaintext_padding))
	msg_block=binascii.hexlify(chr(plaintext_padding)*plaintext_padding)
	for padding in range((plaintext_padding+1),17):
		successful_guess = guess_byte(ctext, ctext_block_index, msg_block, padding)
		if successful_guess:
			print("successful_guess = " + str(successful_guess))
			msg_block = hex_a_number(successful_guess) + msg_block  # working forwards from the end of the block
			print("msg_block = " + msg_block)
		else:
			print("In guess_message_block: wasn't able to guess any byte!")
	print("Just decrypted a message block: " + msg_block)
	return msg_block




def decrypt(ctext, filename_stem = "./saved_message_block_"):
	n_blocks = len(ctext)/32
	message = ""
	for i in range(0,n_blocks-2):
		msg_block = guess_message_block(ctext,ctext_block_index=i)
		message += msg_block
		print("decrypted message after handling block " + str(i) + ": " + message)
		save_message_block(msg_block, filename=filename_stem+str(i))
	last_message_block = guess_last_message_block(ctext)
	save_message_block(last_message_block, filename=filename_stem+str(n_blocks-2))
	message = ""
	for i in range(0, n_blocks-1):
		this_message_block = load_message_block(filename="./saved_message_block_"+str(i))
		print("message_block["+str(i)+"] = " + this_message_block)
		message += this_message_block
	print("Full message: " + message)
	print("Unhexlified message: " + binascii.unhexlify(message))

# There's a 1/256 chance this will fail because randomly the last bit in the 
# decrypted message is 0x01. To make this more robust, I should probably 
# do some error catching. But for this challenge I'll take my chances and 
# not worry about that edge case. Write something sloppy, then improve it.
def decrypt_random_block(ctext, filename_stem = "./saved_message_block_"):
	n_blocks = 2 # Only done for first pass for encrypting a new message
	message = ""
	for i in range(0,n_blocks-1):
		msg_block = guess_message_block(ctext,ctext_block_index=i)
		message += msg_block
		print("decrypted message after handling block " + str(i) + ": " + message)
		save_message_block(msg_block, filename=filename_stem+str(i))
	message = ""
	for i in range(0, n_blocks-1):
		this_message_block = load_message_block(filename=filename_stem+str(i))
		print("message_block["+str(i)+"] = " + this_message_block)
		message += this_message_block
	print("Full message: " + message)
	print("Unhexlified message: " + binascii.unhexlify(message))
	return(message)





p = spawn_process(local=local)

p.readuntil(": ")
ctext = p.readuntil("\n")
# strip trailing newline
ctext = ctext[0:len(ctext)-1]
print("ciphertext = " + ctext)
print("ciphertext length = " + str(len(ctext)))

ctext = "5468697320697320616e204956343536bade59109764febea2c7750a4dae94dc9d494afe7d2f6f65fb1396791585bc03001275db3d5dc7666a39a5b1159e261a7bce4dd133a77c975cbba1ddb3751bc69f88ebbf9d2ca59cda28230eddb23e16"




cookie = decrypt(ctext)
print("The decrypted cookie is " + cookie)

########     E  N  C  R  Y  P  T  I  O  N     F  U  N  C  T  I  O  N  S     #########


### TODO for a library function: just take the remaining code here and make it into its 
### own function, and improve on step 3 as explained in the comments.
## To encrypt a message:
## 1. Split it up into desired message blocks
## 2. Create a ciphertext block for the back that can be any value, and a random IV
## 3. Determine the value of the plaintext that would have produced that random message.
##    For this submission I can probably treat it like a message chunk that 
##    does not end in padding. In theory the plaintext could accidentally end 
##    in something like (0x02, 0x02), so I would need to deal with that when 
##    generalizing this into a library function, but for now I'll ignore that edge case.
## 4. Bit-flip the IV to produce the desired plaintext and confirm that I can actually
##    produce the desired plaintext. 
##    (This first plaintext needs to contain the padding bytes.)
## 5. The rest I can do in a loop:
##    a. Tack the IV onto the front.
##    b. Decrypt the first ciphertext block after the IV. 
##    c. Bit flip the IV to produce the desired plaintext and confirm it works.

## 1. Split it up into desired message blocks
desired_msg = "{\"username\": \"guest\", \"expires\": \"2020-01-07\", \"is_admin\" : \"true\"}\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d"
msg_blocks = get_text_blocks(binascii.hexlify(desired_msg))
print("msg_blocks: " + str(msg_blocks))

## 2. Create a ciphertext block for the back that's anything, and a random IV
last_ct_block = "00"*16
IV = binascii.hexlify("ABCDEFGHIJKLMNOP")

## 3. Determine the value of the plaintext that would have produced that random message.
##    Keep in mind that for this submission treat it like a message chunk that 
##    does not end in padding
this_ct = IV + last_ct_block
print("this_ct = " + this_ct)
this_msg = decrypt_random_block(this_ct, filename_stem = "./saved_remote_forged_message_pass_1_block_")
print("this_msg = " + str(this_msg))


## 4. Bit-flip the IV to produce the desired plaintext and confirm it works. 
##    (This first plaintext needs to contain the padding bytes.)
def flip_ct_bits(plaintext_block_n_original, plaintext_block_n_modified, ctext_block_n_minus_1):
	return xor_two_hex_strings(xor_two_hex_strings(plaintext_block_n_original, plaintext_block_n_modified), ctext_block_n_minus_1)

n = len(msg_blocks)
print("n = " + str(n))
new_ct_n_minus_1 = flip_ct_bits(plaintext_block_n_original=this_msg, 
							plaintext_block_n_modified=msg_blocks[(n-1)],
							ctext_block_n_minus_1=IV)
new_ct = new_ct_n_minus_1 + last_ct_block
print("new ciphertext to produce desired final message block: " + new_ct)
# Works when submitted back to the server!

# Now loop the rest.
ct = new_ct
current_ct = new_ct
##    a. Tack the IV onto the front.
##    b. Decrypt the first ciphertext block after the IV. 
##    c. Bit flip the IV to produce the desired plaintext and confirm it works.
for i in range(0,n-1):
	# a. Just grab the most recent ciphertext and tack the IV onto it.
	current_ct = IV + ct[0:32]
	print("i = " + str(i))
	print("current_ct = " + current_ct)
	## b. Decrypt the first ciphertext block after the IV.
	this_msg = decrypt_random_block(current_ct, filename_stem = "./saved_remote_forged_message_pass_"+str(i+2)+"_block_")
	print("this_msg = " + str(this_msg))
	new_ct_n_minus_1 = flip_ct_bits(plaintext_block_n_original=this_msg, 
									plaintext_block_n_modified=msg_blocks[(n-(i+2))],
							ctext_block_n_minus_1=IV)
	ct = new_ct_n_minus_1 + ct
	print("i = " + str(i) + ". New ciphertext to produce desired final message block(s): " + ct)
	save_message_block(ct, filename="./saved_remote_ct_round_"+str(i))
exit(0)
