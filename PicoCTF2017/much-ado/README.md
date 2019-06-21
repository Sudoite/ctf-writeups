# Much Ado About Hacking

This challenge is a 165-point, Level 3 reverse engineering challenge for PicoCTF 2017. The challenge is to reverse what appears at first glance to be a play script to find a flag:

    Much Ado About Hacking.

    Benedick, a budding young hacker.
    Beatrice, a veteran exploiter.
    Don Pedro, a good friend of the others.
    Don John, he is just kinda there.
    Achilles,  I thought he was from Greece.
    Cleopatra, now this is just getting ridiculous.


    					  Act I: Also the last act.

    				 Scene I: Benedick learns his place.

    [Enter Beatrice and Don John]

    Beatrice:
    You are nothing!

    [Exit Don John]
    [Enter Don Pedro]

    Beatrice:
    You are nothing!

    [Exit Don Pedro]
    [Enter Achilles]

    Beatrice:
    You are as proud as a bold brave gentle noble amazing hero.
    ...
        Scene II: Benedick strengthens his memory.

    Beatrice:
    Open your mind! Remember yourself.

    Benedick:
    You are as red as the sum of yourself and a tree.
    Am I as lovely as a cunning charming honest peaceful bold pony?

    Beatrice:
    If not, let us return to scene II.

    Benedick:
    You are as worried as the sum of yourself and a Microsoft.

    Beatrice:
    Recall your father's disappointment!

In particular, the challenge is to determine a specific input string that will produce a specific [output](./ending.txt) attached to the challenge.

### The Setup

Casual inspection of the code suggests that the character names are variables, some variables get initialized to zero, there appears to be a `while` loop in "Scene II", adjectives are used to determine numbers used in arithmetic operations (with positive adjectives corresponding to positive numbers and negative adjectives corresponding to negative numbers), and some actions may save variables to memory or load them from memory. Some quick searching shows this to be code written in the esoteric [Shakespeare Programming Language (SPL)](http://shakespearelang.sourceforge.net/report/shakespeare/).

It would be entertaining to convert the code to C manually, but I found it faster and more accurate to use a tool to translate SPL to C. I first tried using the developers' original [translator](http://shakespearelang.sourceforge.net/), but as the tool was written 15 years ago, it is [not able to be compiled](https://stackoverflow.com/questions/43268064/problems-compiling-the-shakespeare-programming-language-spl2c#) with modern versions of `gcc`. That said, I was able to compile [this](https://bitbucket.org/FlorianPommerening/spl-fixes/downloads/0) modified version of the SPL translator, written by Florian Pommerening. [Here's](./much_ado.c) the compiled code.

### Reversing

The first step of the reversing process is to read and understand the C code. The translator generates two files, `much_ado.c` and `spl.h`. The section of the code corresponding to Scene I just initializes some variables; the main work horse is Scene II, which converts user input to output. First, the input characters are converted to ASCII numbers (e.g. 'a' = 97). These numbers are then converted to output numbers and then their corresponding ASCII characters via the following formula. Assuming that `inputs` is a zero-based array of `N` numbers corresponding to ASCII characters:

    if i == 0:
      outputs[i] = inputs[N-1] // base case
    else:
      outputs[i] = (inputs[N-i] - 32 + inputs[N-i-1] - 32) % 96
                    + 32 // recursive case


With a little algebra, we can solve for `inputs[i]`:

    if i == 0:
      inputs[N-1] = outputs[i] // base case
      inputs[N-i-1] = outputs[i] + 32 + 96c - inputs[N-i]
                      // recursive case; c is an integer

The integer `c` is unknown, but we know that each value of the output must be in the range 32 to 128, so we can now solve for `inputs` exactly.

Here is the code to do the reversing:

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

Running the above code with the provided output ("tu1|\h+&g\OP7@% :BH7M6m3g=") produces the flag: `Its@MidSuMm3rNights3xpl0!t`. Huzzah! Foolish problem, make thy sepulchure and creep into it far before thy time. (Henry VI I.i)
