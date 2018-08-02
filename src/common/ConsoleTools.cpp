// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "ConsoleTools.hpp"

#include <stdio.h>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <io.h>
#include "platform/Files.hpp"
#include "platform/Windows.hpp"
#else
#include <termios.h>
#include <unistd.h>
#include <boost/concept_check.hpp>
#include <cstring>
#include <iostream>

#endif

namespace common {
namespace console {

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

	static WORD win_colors[] = {// default
	    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
	    // main
	    FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_RED, FOREGROUND_RED | FOREGROUND_GREEN,
	    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, FOREGROUND_GREEN | FOREGROUND_BLUE,
	    FOREGROUND_RED | FOREGROUND_BLUE,
	    // bright
	    FOREGROUND_BLUE | FOREGROUND_INTENSITY, FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	    FOREGROUND_RED | FOREGROUND_INTENSITY, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
	    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
	    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY};

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), win_colors[static_cast<size_t>(color)]);

#else

	static const char *ansi_colors[] = {// default
	    "\033[0m",
	    // main
	    "\033[0;34m", "\033[0;32m", "\033[0;31m", "\033[0;33m", "\033[0;37m", "\033[0;36m", "\033[0;35m",
	    // bright
	    "\033[1;34m", "\033[1;32m", "\033[1;31m", "\033[1;33m", "\033[1;37m", "\033[1;36m", "\033[1;35m"};

	std::cout << ansi_colors[static_cast<size_t>(color)];

#endif
}

UnicodeConsoleSetup::UnicodeConsoleSetup() {
#ifdef _WIN32
	if (IsValidCodePage(CP_UTF8)) {
		SetConsoleOutputCP(CP_UTF8);
		SetConsoleCP(CP_UTF8);
	}
	old_buf = std::cout.rdbuf(this);
#else
	boost::ignore_unused_variable_warning(old_buf);
#endif
}
UnicodeConsoleSetup::~UnicodeConsoleSetup() {
#ifdef _WIN32
	std::cout.rdbuf(old_buf);
	old_buf = nullptr;
#endif
}
int UnicodeConsoleSetup::sync() {
	printf("%s", str().c_str());
	fflush(stdout);
	str(std::string());
	return 0;
}
bool UnicodeConsoleSetup::getline(std::string &line, bool hide_input) {
//	std::string test;
//	std::cout << "Enter test visible: " << std::flush;
//	if (!console_setup.getline(test)) {
//		return 0;
//	}
//	std::cout << "You entered {" << test << "} Enter test invisible: " << std::flush;
//	if (!console_setup.getline(test, true)) {
//		return 0;
//	}
//	std::cout << "You entered {" << test << "}" << std::flush;
//	return 1;
#ifdef _WIN32
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode    = 0;
	if (hide_input) {
		GetConsoleMode(hStdin, &mode);
		SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
	}
	wchar_t wstr[4096];  // TODO - read in chunks?
	unsigned long read = 0;
	bool result        = ReadConsoleW(hStdin, wstr, sizeof(wstr) / sizeof(*wstr), &read, NULL) != 0;
	if (result) {
		line = platform::FileStream::utf16_to_utf8(std::wstring(wstr, read));
		if (!line.empty() && line.back() == '\n')
			line.pop_back();
		if (!line.empty() && line.back() == '\r')
			line.pop_back();
	} else {
		char buf = 0;
		line.clear();
		while (ReadFile(hStdin, &buf, 1, &read, nullptr)) {
			line.push_back(buf);
			if (buf == '\n') {
				result = true;
				break;
			}
		}
		if (!line.empty() && line.back() == '\n')
			line.pop_back();
		if (!line.empty() && line.back() == '\r')
			line.pop_back();
	}
	if (hide_input)
		SetConsoleMode(hStdin, mode);
#else
	termios oldt{};
	if (hide_input) {
		tcgetattr(STDIN_FILENO, &oldt);
		termios newt = oldt;
		newt.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	}
	bool result = !!std::getline(std::cin, line);
	if (hide_input)
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
	return result;
}
}
}
