#reverse-activate.py

# Letter must be 0-9 or A-Z, not checked here
def order(letter):
	if letter in '0123456789':
		return ord(letter)-0x30
	else:
		#print("order " + letter + " = " + str(ord(letter)-0x37))
		return ord(letter)-0x37

def get_validation_number(activation_key):
	result = 0
	if len(activation_key) != 16:
		print("Error: activation key the wrong length.")
		exit(0)
	# Use all letters except last one here
	for i in range(0,15):
		result += (i+1)*(order(activation_key[i])+1)
	return result

def calculate_last_hex_letter(checksum):
	c = checksum * 954437177 >> 32
	print("c = " + hex(c))
	c_prime = (c - c%8 + (c >> 3))*4
	print("c' = " + hex(c_prime))
	result = checksum-c_prime
	print("result = " + hex(result))

print(str(get_validation_number('ABCDEFABCDEFABCD')))

vn = get_validation_number('ABCDEFABCDEFABCD')
calculate_last_hex_letter(vn)
