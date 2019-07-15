# solve-lithp.py
# by Sudoite

ct = [8930,15006,8930,10302,11772,13806,13340,11556,12432,13340,10712,10100,11556,12432,9312,10712,10100,10100,8930,10920,8930,5256,9312,9702,8930,10712,15500,9312]
order = [19,4,14,3,10,17,24,22,8,2,5,11,7,26,0,25,18,6,21,23,9,13,16,1,12,15,27,20]

flag = ['Y']*28 # Initialization
print(ct)
print(order)
flag2 = ['Z']*28

def solve_quadratic(n):
	return (1+pow(1+4*n,0.5))*0.5

for i in range(28):
	flag[i] = chr(int(solve_quadratic(ct[i])))

for i in range(28):
	for j in range(28):
		if order[j]==i:
			flag2[i]=flag[j]

print("rough flag: " + str(flag) + "\n")
print("unscrambled flag: " + str(flag2) + "\n")
print(''.join(flag2))