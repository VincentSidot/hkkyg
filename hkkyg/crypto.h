#pragma once
#include <Windows.h>
#include <stdint.h>
#include <string.h>

namespace crypto
{
	class XOR
	{
	public:
		XOR(const void* key,size_t keylen);
		~XOR();
		size_t encrypt(const void* input, void* output,size_t len); // return 0 if okay
		size_t decrypt(const void* input, void* output, size_t len); // return 0 if okay

	private:
		void* m_key;
		size_t m_keylen;
	};

}

