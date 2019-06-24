from pwn import *

def test_9_digit_number(n_9_digits):
	n = n_9_digits
	e = (n/10000) % 10
	# Short circuit
	if e != 1:
		return False
	a = n % 10
	b = (n/10) % 10
	c = (n/100) % 10
	d = (n/1000) % 10
	f = (n/100000) % 10
	g = (n/1000000) % 10
	h = (n/10000000) % 10
	i = (n/100000000) % 10
	abcd = n % 10000
	fghi = n / 100000
	if (b + 10*d - f - 10*i - 1) != 0:
		return False
	if (-20*b - 2*c + g + 10*h - 8) != 0:
		return False
	if (-3*a - 30*c + 10*f + h) != 0:
		return False
	if n % (abcd*fghi) != 1337:
		log.info("Made it to last test and failed: n = " + str(n), " tested " + str(n%(abcd*fghi)) + ".\n")
		return False
	log.info("The number is " + str(n_9_digits))
	return True

log.info(test_9_digit_number(988319640))
log.info(test_9_digit_number(999999999))

count = 0
count += 1
while count < pow(2,32):
	if test_9_digit_number(count):
		log.info("Returned true.\n")
		break
	if (count % 1000000) == 0:
		log.info("count = " + str(count) + ".\n")
	count += 1
# Got it! 790317143
