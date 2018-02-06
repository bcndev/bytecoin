// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <string>
#include <array>
#include "common/ConsoleTools.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>

//#undef ERROR

namespace logging {

enum Level {
	FATAL = 0,
	ERROR = 1,
	WARNING = 2,
	INFO = 3,
	DEBUGGING = 4,
	TRACE = 5
};

using namespace common::console; // We want Color enum and members here 
/*using common::console::Color;

using common::console::Color::Default;

using common::console::Color::Blue;
using common::console::Color::Green;
using common::console::Color::Red;
using common::console::Color::Yellow;
using common::console::Color::White;
using common::console::Color::Cyan;
using common::console::Color::Magenta;

using common::console::Color::BrightBlue;
using common::console::Color::BrightGreen;
using common::console::Color::BrightRed;
using common::console::Color::BrightYellow;
using common::console::Color::BrightWhite;
using common::console::Color::BrightCyan;
using common::console::Color::BrightMagenta;*/

/*extern const std::string BLUE;
extern const std::string GREEN;
extern const std::string RED;
extern const std::string YELLOW;
extern const std::string WHITE;
extern const std::string CYAN;
extern const std::string MAGENTA;
extern const std::string BRIGHT_BLUE;
extern const std::string BrightGreen;
extern const std::string BrightRed;
extern const std::string BRIGHT_YELLOW;
extern const std::string BRIGHT_WHITE;
extern const std::string BRIGHT_CYAN;
extern const std::string BRIGHT_MAGENTA;
extern const std::string DEFAULT;*/

class ILogger {
public:
	const static char COLOR_PREFIX;
	const static char COLOR_LETTER_DEFAULT;

	const static std::array<std::string, 6> LEVEL_NAMES;

	virtual void operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) = 0;
	virtual ~ILogger() {}
};

std::ostream &operator<<(std::ostream &out, common::console::Color color);

}


