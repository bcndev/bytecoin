// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <array>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <string>
#include "common/ConsoleTools.hpp"

namespace logging {

enum Level { FATAL = 0, ERROR = 1, WARNING = 2, INFO = 3, DEBUGGING = 4, TRACE = 5 };

using namespace common::console;  // We want Color enum and members here

class ILogger {
public:
	const static char COLOR_PREFIX;
	const static char COLOR_LETTER_DEFAULT;

	const static std::array<std::string, 6> LEVEL_NAMES;

	virtual void write(
	    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) = 0;
	virtual ~ILogger() {}
};

std::ostream &operator<<(std::ostream &out, common::console::Color color);
}
