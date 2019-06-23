# Blind

This is a 200-point cryptography problem from VolgaCTF2019.

This problem uses RSA. The challenge is to run `cat flag.txt`, but the command must be sent as a base 64-encoded string preceded by a proper signature. The user can get the server to sign a command but the problem is they can't sign a `cat flag.txt` command. So, somehow we need to get the secret key by signing a different command.

If `d` were small then I could send a really short message, such that `m^d < n`. Then I would just take the log of `m^d` base `m` to recover the secret key. But that doesn't work here: sending m='\x02' gives me back an odd number for the signature (n is odd).  

Aha! A look back at Dan Boneh's paper, [20 Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf), gives the answer and the name of the problem. I need to do a "blinding attack", wherein I replace the command "cat flag" with that multiplied by a random number `r` raised to the `e` power. Then, once I submit that new message `M'` and get back a signature `S'`, I divide `S'` by `r` to get the signature for `cat flag`. In theory that's easy, but the implementation was pretty tricky for me. I had to make sure that `M'` didn't contain any tabs, newlines, carriage returns, or spaces, and that single quotes, double quotes, and backslashes were escaped. Lacking experience in this area I discovered a lot of that by trial and error and some careful use of print statements in `local.py`, so it took a couple of hours to implement.

But here's the satisfying result:
`VolgaCTF{B1ind_y0ur_tru3_int3nti0n5}`

And 200 points!

[Here's](./exploit-blind.py) the exploit code.

### Comparison with other approaches

Generally the approaches posted to CTF Time are the same as this one, but there are quite a bit of differences in terms of the Python implementation. I particularly liked [this write-up](https://devel0pment.de/?p=1210), which is very clear and shows a simple example of why the math works. I would like to clean up this code and may revisit this write-up in the future, but at the moment when I'm playing catch-up with posting write-ups, I'm just posting my code from the competition.
