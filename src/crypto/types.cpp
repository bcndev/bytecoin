// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "types.hpp"
#include <iostream>

namespace crypto {

static std::string to_hex(const void *data, size_t size) {
	std::string text(size * 2, ' ');
	for (size_t i = 0; i < size; ++i) {
		text[i * 2]     = "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] >> 4];
		text[i * 2 + 1] = "0123456789abcdef"[static_cast<const uint8_t *>(data)[i] & 15];
	}
	return text;
}

std::ostream &operator<<(std::ostream &out, const EllipticCurvePoint &v) {
	return out << to_hex(v.data, sizeof(v.data));
}
std::ostream &operator<<(std::ostream &out, const EllipticCurveScalar &v) {
	return out << to_hex(v.data, sizeof(v.data));
}
std::ostream &operator<<(std::ostream &out, const Hash &v) { return out << to_hex(v.data, sizeof(v.data)); }

}  // namespace crypto
