// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "ConsoleLogger.hpp"
#include <iostream>
#include <unordered_map>
#include "common/ConsoleTools.hpp"

namespace logging {

using common::console::Color;

std::mutex ConsoleLogger::mutex;

ConsoleLogger::ConsoleLogger(Level level) : CommonLogger(level) {}

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
