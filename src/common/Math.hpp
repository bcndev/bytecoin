// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <vector>

namespace common {

template<class T>
T median_value(std::vector<T> *v) {
	if (v->empty())
		return T();

	auto n = v->size() / 2;
	std::sort(v->begin(), v->end());

	if (v->size() % 2)  // 1, 3, 5...
		return (*v)[n];
	return ((*v)[n - 1] + (*v)[n]) / 2;  // 2, 4, 6...
}
}
