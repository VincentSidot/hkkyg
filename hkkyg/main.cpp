#include <iostream>
#include "crypto.h"

int main(int argc, char** argv)
{
	char str1[] = "Hello world !";
	char str2[sizeof(str1)];
	crypto::XOR test(static_cast<const void*>("test"), 4);
	test.encrypt(str1, str2, sizeof(str1));
	test.decrypt(str2, str1, sizeof(str1));

	std::cout << str1 << std::endl;
	std::cin.ignore().get();

	return 0;
}