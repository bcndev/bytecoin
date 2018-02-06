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

#include "ConsoleLogger.hpp"
#include <iostream>
#include <unordered_map>
#include "common/ConsoleTools.hpp"


namespace logging {

using common::console::Color;

std::mutex ConsoleLogger::mutex;

ConsoleLogger::ConsoleLogger(Level level) : CommonLogger(level) {
}

void ConsoleLogger::do_log_string(const std::string &message) {
	std::lock_guard<std::mutex> lock(mutex);
//	bool readingText = true;
	bool changedColor = false;
//	std::string color = "";

/*	static std::unordered_map<std::string, Color> colorMapping = {
			{BLUE,           Color::Blue},
			{GREEN,          Color::Green},
			{RED,            Color::Red},
			{YELLOW,         Color::Yellow},
			{WHITE,          Color::White},
			{CYAN,           Color::Cyan},
			{MAGENTA,        Color::Magenta},

			{BRIGHT_BLUE,    Color::BrightBlue},
			{BrightGreen,   Color::BrightGreen},
			{BrightRed,     Color::BrightRed},
			{BRIGHT_YELLOW,  Color::BrightYellow},
			{BRIGHT_WHITE,   Color::BrightWhite},
			{BRIGHT_CYAN,    Color::BrightCyan},
			{BRIGHT_MAGENTA, Color::BrightMagenta},

			{DEFAULT,        Color::Default}
	};*/

	for (size_t charPos = 0; charPos < message.size(); ++charPos) {
		if (charPos + 1 < message.size() && message[charPos] == ILogger::COLOR_PREFIX) {
			charPos += 1;
			Color color = static_cast<Color>(message[charPos] - ILogger::COLOR_LETTER_DEFAULT);
			std::cout << std::flush;
			common::console::set_text_color(color);
			changedColor = true;
		} else {
			std::cout << message[charPos];
		}
	}

	if (changedColor) {
		std::cout << std::flush;
		common::console::set_text_color(Color::Default);
	}
}

}
