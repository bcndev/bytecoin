// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Time.hpp"
#include <ctime>
#include <iostream>
#include "common/Invariant.hpp"

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#if defined(_WIN32)
#include "platform/Windows.hpp"

uint32_t platform::now_unix_timestamp(uint32_t *usec) {
	if (usec)
		*usec = 0;
	// TODO - better resolution on Windows
	return static_cast<uint32_t>(std::time(nullptr));
}

#else
#include <sys/time.h>

uint32_t platform::now_unix_timestamp(uint32_t *usec) {
	timeval tv{};
	gettimeofday(&tv, nullptr);
	if (usec)
		*usec = tv.tv_usec;
	//	auto was_time = uint32_t(std::time(nullptr));
	//	if (abs(int(tv.tv_sec) - int(was_time)) > 1)
	//		std::cout << "bad time" << std::endl;  // TODO - remove after checking on Mac
	return static_cast<uint32_t>(tv.tv_sec);
}

#endif

static int time_multiplier = 1;

int platform::get_time_multiplier_for_tests() { return time_multiplier; }
void platform::set_time_multiplier_for_tests(int multiplier) {
	invariant(multiplier >= 1, "");
	time_multiplier = multiplier;
}
