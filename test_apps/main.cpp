#include <cstdlib>
#include <cstdio>
#include <Windows.h>

int main(int argc, char** argv)
{
	int* test;
	test = new int(12);
	printf("0x%x", test);
	getchar();
	while (true)
	{
		printf("%d\n", *test);
		Sleep(100);
	}
	return 0;
}