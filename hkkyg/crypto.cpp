#include "crypto.h"

crypto::XOR::XOR(const void* key, size_t keylen)
{
	m_keylen = keylen;
	m_key = malloc(keylen);
	memcpy(m_key, key, keylen);
}

crypto::XOR::~XOR()
{
	if (m_key != nullptr)
	{
		free(m_key);
	}
	m_key = nullptr;
}

size_t crypto::XOR::encrypt(const void * input, void * output, size_t len)
{
	DWORD oldprotect;
	bool test = VirtualProtect(output, len, PAGE_READWRITE, &oldprotect);
	if (test)
		return test;
	for (size_t i = 0; i < len; ++i)
	{
		*(static_cast<unsigned char*>(output) + i) = *(static_cast<const unsigned char*>(input) + i) ^ *(static_cast<unsigned char*>(m_key) + i % m_keylen);
	}
	return test = VirtualProtect(output, len, oldprotect, nullptr);
}

size_t crypto::XOR::decrypt(const void * input, void * output, size_t len)
{
	DWORD oldprotect;
	bool test = VirtualProtect(output, len, PAGE_READWRITE, &oldprotect);
	if (test)
		return test;
	for (size_t i = 0; i < len; ++i)
	{
		*(static_cast<unsigned char*>(output) + i) = *(static_cast<const unsigned char*>(input) + i) ^ *(static_cast<unsigned char*>(m_key) + i % m_keylen);
	}
	return test = VirtualProtect(output, len, oldprotect, nullptr);
}
