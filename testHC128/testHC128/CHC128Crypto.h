#pragma once
#include "hc128.h"
class CHC128Crypto
{
public:
	struct hc128_context _sndCtx;
	uint8_t			     _sndKeyStream[64];
	int                  _sndKeyOffset;

	struct hc128_context _rcvCtx;
	uint8_t			     _rcvKeyStream[64];
	int                  _rcvKeyOffset;

	CHC128Crypto();
	~CHC128Crypto();
	void init();
	void decryptForSend(uint8_t* data, int len, uint8_t* out);
	void decryptForRcv(uint8_t* data, int len, uint8_t* out);

};

