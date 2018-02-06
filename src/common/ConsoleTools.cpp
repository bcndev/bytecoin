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

#include "ConsoleTools.hpp"

#include <stdio.h>
#include <iostream>
#include <sstream>

#ifdef _WIN32
	#include "platform/Windows.hpp"
	#include <io.h>
#else
	#include <iostream>
	#include <unistd.h>
	#include <cstring>
	#include <boost/concept_check.hpp>
#endif

namespace common { namespace console {

bool is_console_tty() {
#if defined(_WIN32)
	static bool istty = 0 != _isatty(_fileno(stdout));
#else
	static bool istty = 0 != isatty(fileno(stdout));
#endif
	return istty;
}

void set_text_color(Color color) {
	if (!is_console_tty()) {
		return;
	}

	if (color < Color::Default || color > Color::BrightMagenta) {
		color = Color::Default;
	}

#ifdef _WIN32

	static WORD winColors[] = {
	  // default
	  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	  // main
	  FOREGROUND_BLUE,
	  FOREGROUND_GREEN,
	  FOREGROUND_RED,
	  FOREGROUND_RED | FOREGROUND_GREEN,
	  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	  FOREGROUND_GREEN | FOREGROUND_BLUE,
	  FOREGROUND_RED | FOREGROUND_BLUE,
	  // bright
	  FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	  FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	  FOREGROUND_RED | FOREGROUND_INTENSITY,
	  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	  FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	  FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	  FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY
	};

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), winColors[static_cast<size_t>(color)]);

#else

	static const char *ansiColors[] = {
			// default
			"\033[0m",
			// main
			"\033[0;34m",
			"\033[0;32m",
			"\033[0;31m",
			"\033[0;33m",
			"\033[0;37m",
			"\033[0;36m",
			"\033[0;35m",
			// bright
			"\033[1;34m",
			"\033[1;32m",
			"\033[1;31m",
			"\033[1;33m",
			"\033[1;37m",
			"\033[1;36m",
			"\033[1;35m"
	};

	std::cout << ansiColors[static_cast<size_t>(color)];

#endif
}

	UnicodeConsoleSetup::UnicodeConsoleSetup(){
#ifdef _WIN32
		SetConsoleOutputCP(CP_UTF8);
		old_buf = std::cout.rdbuf(this);
#else
		boost::ignore_unused_variable_warning(old_buf);
#endif
	}
	UnicodeConsoleSetup::~UnicodeConsoleSetup() {
#ifdef _WIN32
		std::cout.rdbuf(old_buf); old_buf = nullptr;
#endif
	}
	int UnicodeConsoleSetup::sync() {
		printf("%s", str().c_str());
		fflush(stdout);
		str(std::string());
		return 0;
	}
}}

