#include <iostream>
#include "CHC128Crypto.h"
CHC128Crypto::CHC128Crypto()
{
	_sndKeyOffset = 0;	
	_rcvKeyOffset = 0;
}
CHC128Crypto::~CHC128Crypto()
{

}
void CHC128Crypto::init()
{
	uint8_t key[16] = { 0x42,0x5B,0x29,0xFD,0xB7,0x53,0xC5,5,0x83,0x77,0xE8,0xA,0x50,0x17,0x80,0x75 };
	uint8_t iv[16] = { 0xDE, 0xAD, 0x45, 0xC1, 0x2A, 0xC8, 0x93, 0xCE, 0xAA,0, 0xBF, 0xB6, 0x7B, 0x40, 0x19, 0xA7 };

	hc128_set_key_and_iv(&_sndCtx, (uint8_t*)key, 16, (const uint8_t*)iv, 16);
	hc128_set_key_and_iv(&_rcvCtx, (uint8_t*)key, 16, (const uint8_t*)iv, 16);

	hc128_generate_keystream(&_sndCtx, (uint32_t*)_sndKeyStream);
	hc128_generate_keystream(&_rcvCtx, (uint32_t*)_rcvKeyStream);
}

void CHC128Crypto::decryptForRcv(uint8_t* data, int len, uint8_t* out)
{
	memset(out, 0, 1024);
	for (int i = 0; i < len; i++)
	{
		if (_rcvKeyOffset >= 64)
		{
			hc128_generate_keystream(&_rcvCtx, (uint32_t*)_rcvKeyStream);
			_rcvKeyOffset = 0;
		}

		out[i] = data[i] ^ _rcvKeyStream[_rcvKeyOffset];
		_rcvKeyOffset++;
	}
}

void CHC128Crypto::decryptForSend(uint8_t* data, int len, uint8_t* out)
{
	memset(out, 0, 1024);
	for (int i = 0; i < len; i++)
	{
		if (_sndKeyOffset >= 64)
		{
			hc128_generate_keystream(&_sndCtx, (uint32_t*)_sndKeyStream);
			_sndKeyOffset = 0;
		}

		out[i] = data[i] ^ _sndKeyStream[_sndKeyOffset];
		_sndKeyOffset++;
	}
}


