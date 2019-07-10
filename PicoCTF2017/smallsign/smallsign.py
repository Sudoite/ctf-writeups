#!/usr/bin/python -u

from Crypto.PublicKey import RSA
import random
import signal

key = RSA.generate(2048)
flag = open("./flag.txt").read()

print("You have 60 seconds to forge a signature! Go!")
# In 60 seconds, deliver a SIGALRM and terminate
signal.alarm(60)

print("N: " + str(key.n))
print("e: " + str(key.e))

'''
sig2 = key.sign(2, None)
print("Signature of 2:" + str(sig2[0]))
sig4 = key.sign(4, None)
print("Signature of 4:" + str(sig4[0]))
forge = sig2[0] * sig2[0] % key.n
print("Forged signature of 4:" + str(forge))
'''

while True:
    m = long(raw_input("Enter a number to sign (-1 to stop): "))
    if m == -1:
        break
    sig = key.sign(m, None)
    print("Signature: " + str(sig[0]))

challenge = long(random.randint(0, 2**32))
#challenge = long(random.randint(0, 2**7))

print("Challenge: " + str(challenge))
s = long(raw_input("Enter the signature of the challenge: "))
print("s class = " + str(s.__class__))
if key.verify(challenge, (s, None)):
    print("Congrats! Here is the flag:" + flag)
else:
    print("Nope, that's wrong!")
