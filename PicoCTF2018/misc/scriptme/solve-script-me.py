

# Script me!


# Rule priority:
# 1. 


from pwn import *
from time import sleep



def get_max_depth(addend):
	depth = 0
	max_depth = 0
	for i in range(0,len(addend)):
		if addend[i] == '(':
			depth += 1
			if depth > max_depth:
				max_depth += 1
		elif addend[i] == ')':
			depth -= 1
		else:
			print("Error in get_max_depth: unexpected character: " + addend[i])
			return -1
	if depth != 0:
		print("Error in get_max_depth: unbalanced parentheses in addend: " + addend)
		return -1
	return max_depth

def get_a_token(formula):
	i = 0
	token = ''
	while i < len(formula) and formula[i] in '()':
		char = formula[i]
		token += char
		i += 1
	# Space over to start of next token
	while i < len(formula) and formula[i] not in '()':
		i += 1
	# truncate formula
	if i < len(formula):
		formula = formula[i:len(formula)]
	else:
		formula = ''
	return token, formula

# unit tests for get_a_token
#new_token, new_formula = get_a_token('()')
#print(get_a_token('()'))
#print(get_a_token('(()()(())) + ()()'))
#print(get_a_token('(()()(()))'))
#print(get_a_token(''))
#print(get_a_token('(()()(())) + ()() + ()'))

def tokenize(formula):
	tokens = []
	while len(formula) > 0:
		next_token, formula = get_a_token(formula)
		tokens += [next_token]
	return tokens

# unit tests for tokenize
#print(tokenize('()'))
#print(tokenize('(()()(())) + ()()'))
#print(tokenize('(()()(()))'))
#print(tokenize(''))
#print(tokenize('(()()(())) + ()() + ()'))

def combine(token1, token2):
	return token1 + token2

# TODO: I probably need to call add_two again from inside here
def absorb_right(token1, token2):
	#depth1 = get_max_depth(token1) # Not efficient but fine
	result = token1[0:len(token1)-1]
	result += token2
	result += ')'
	return result

# TODO: I probably need to call add_two again from inside here
def absorb_left(token1, token2):
	result = '('
	result += token1
	result += token2[1:len(token2)]
	return result

#print(combine('(())','()'))
#print(absorb_right('((()))','()'))
#print(absorb_right('((()))','(())'))
#print(absorb_left('()', '((()))'))
#print(absorb_left('(())','((()))'))

def add_two(token1, token2):
	depth1 = get_max_depth(token1)
	depth2 = get_max_depth(token2)
	if depth1 == depth2:
		return combine(token1, token2)
	elif depth1 > depth2:
		return absorb_right(token1, token2)
	elif depth1 < depth2:
		return absorb_left(token1, token2)
	else:
		print("Error in add_two: token1 = " + token1 + " and token2 = " + token2)
		return -1

#print(add_two('()','()'))
#print(add_two('((()))','()'))
#print(add_two('()','((()))'))

def add_all(formula):
	tokens = tokenize(formula)
	token_index = 0
	if len(tokens) < 1:
		return ''
	while len(tokens)>1:
		tmp = add_two(tokens[0],tokens[1])
		tokens[1] = tmp
		del(tokens[0])
	return tokens[0]

#print(add_all('() + ()'))
#print(add_all('() + (()) + ((()))'))
#print(add_all(''))
#print(add_all('(())'))
#print(add_all('((())) + (()) + ()'))

# unit tests for get_max_depth
#print(get_max_depth('()'))
#print(get_max_depth('(((((())))))'))
#print(get_max_depth('(()()()())'))
#print(get_max_depth('((())')) # should be unbalanced parentheses
#print(get_max_depth('()()()b'))
#print(get_max_depth('((())())'))

def solve_question(question_number):
	q = p.recvuntil(" =")
	q = q[0:len(q)-2]
	print("q[" + str(question_number) + "] = " + q)
	a = add_all(q)
	print("a[" + str(question_number) + "] = " + a)
	time.sleep(1)
	p.send(a + "\n")
	time.sleep(0.5)

p = remote('2018shell2.picoctf.com', 7866)

p.recvuntil('warmup.\n')

for question_number in range(4):
	solve_question(question_number)
	p.recvuntil("Correct!\n")
	p.recvuntil("\n")
	p.recvuntil("\n")

solve_question(4)


p.interactive()

