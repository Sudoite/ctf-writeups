
# include <stdio.h>
# include <stdlib.h>
int main(){
	int file_length; // = 0xd5074;
	FILE * rp;
	FILE * wp;
	//srand(1587317623);
	srand(1585599106);
	char * encrypted_filename = "/home/ctf/Documents/WPICTF2020/RE/WannaSigh/test/flag-gif.EnCiPhErEd";
	rp = fopen("flag-gif.EnCiPhErEd","rb");
	wp = fopen("flag.gif","wb");
	fseek(rp, 0, SEEK_END);
	file_length = ftell(rp);
	fseek(rp, 0, SEEK_SET);
	for(int i = 0; i < file_length; i++){
		char tmp = rand()%256;
		fputc(fgetc(rp)^tmp,wp);
	}
	fclose(rp);
	fclose(wp);
	//printf("your integer is %d",1587317623);
	//for (int i = 0; i < 0xd5074; i++){
	//	printf("i = %d and rand = %x\n",i,rand()%256);
	//}
	return 0;
}