
# include <stdlib.h>
# include <stdio.h>

int main(void){
	int N = 26;
	printf("Give me %d characters", N);
	// 1. Need to read the inputs into an array of integers
	// 2. Need to initialize an array of numeric outputs
	// 3. Need to output the numeric outputs as characters
	int outputs[N];
	int inputs[N];
	for (int i = 0; i < N; i++){
		outputs[i] = getc(stdin);
		// printf("outputs[%d] = %d\n",i,outputs[i]);
	}
	

	for (int i= 0; i < N; i++){
		inputs[i] = 0;
	}
	inputs[N-1] = outputs[0]; // base case
	for (int i = 1; i < N; i++){
		int tmp = outputs[i] + 32 - inputs[N-i];
		printf("i = %d\n", i);
		printf("tmp = %d\n", tmp);
		if (tmp < 32){
			tmp += 96;
		}
		else if (tmp > 128){
			tmp -= 96;
		}
		inputs[N-i-1] = tmp;	
	}
	for (int i = 0; i < N; i ++){
		printf("inputs[%d] = %d\n",i,inputs[i]);	
	}
	for (int i = 0; i < N; i++){
		putc(inputs[i], stdout);
	}
	return 0;
}
// Its@MidSuMm3rNights3xpl0!t