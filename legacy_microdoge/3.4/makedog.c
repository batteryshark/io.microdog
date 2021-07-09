/*
MakeDog - A USB 3.4 Microdog Emulator File Creator

Copyright (C) 2014 TheShark Security Collective


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>

typedef struct DogFile{
	unsigned int dog_serial;
	unsigned int dog_password;
	unsigned char vendor_id[8];
	unsigned int mfg_serial;
	unsigned char dog_flashmem[200];
	unsigned int num_keys;
}Dog;
int main(){
	FILE *fd;
	fd = fopen("doge.key","wb");
	Dog dog;
	dog.dog_serial = 0;
	dog.dog_password = 0;
	memset(dog.vendor_id,0x00,8);
	dog.mfg_serial = 0;
	memset(dog.dog_flashmem,0x00,200);
	dog.num_keys = 0;
	fwrite(&dog,sizeof(Dog),1,fd);
	fclose(fd);
return 0;
}
