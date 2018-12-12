// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#pragma pack(push, 1)
struct cryptoEllipticCurvePoint {
	unsigned char data[32];
};
struct cryptoEllipticCurveScalar {
	unsigned char data[32];
};
#pragma pack(pop)
