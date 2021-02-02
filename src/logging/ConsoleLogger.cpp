// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "ConsoleLogger.hpp"
#include <iostream>
#include "common/ConsoleTools.hpp"

namespace logging {

using common::console::Color;

#ifndef __EMSCRIPTEN__
std::mutex ConsoleLogger::mutex;
#endif

ConsoleLogger::ConsoleLogger(Level level) : CommonLogger(level) {}

void ConsoleLogger::do_log_string(const std::string &message) {
#ifndef __EMSCRIPTEN__
	std::lock_guard<std::mutex> lock(mutex);
#endif
	bool changed_color = false;

	for (size_t char_pos = 0; char_pos < message.size(); ++char_pos) {
		if (char_pos + 1 < message.size() && message[char_pos] == ILogger::COLOR_PREFIX) {
			char_pos += 1;
			Color color = static_cast<Color>(message[char_pos] - ILogger::COLOR_LETTER_DEFAULT);
			std::cout << std::flush;
			common::console::set_text_color(color);
			changed_color = true;
		} else {
			std::cout << message[char_pos];
		}
	}

	std::cout << std::flush;
	if (changed_color) {
		common::console::set_text_color(Color::Default);
	}
}
}  // namespace logging
