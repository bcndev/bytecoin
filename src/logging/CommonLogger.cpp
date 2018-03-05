// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "CommonLogger.hpp"

namespace logging {

namespace {

std::string formatPattern(
    const std::string &pattern, const std::string &category, Level level, boost::posix_time::ptime time) {
	std::stringstream s;

	for (const char *p = pattern.c_str(); p && *p != 0; ++p) {
		if (*p == '%') {
			++p;
			switch (*p) {
			case 0:
				break;
			case 'C':
				s << category;
				break;
			case 'D':
				s << time.date();
				break;
			case 'T':
				s << time.time_of_day();
				break;
			case 'l':
				s << ILogger::LEVEL_NAMES[level][0];
				break;
			case 'L':
				s << std::setw(4) << std::left << ILogger::LEVEL_NAMES[level];
				break;
			default:
				s << *p;
			}
		} else {
			s << *p;
		}
	}

	return s.str();
}
}

void CommonLogger::operator()(
    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) {
	if (level <= log_level && m_disabled_categories.count(category) == 0) {
		std::string body2 = body;
		if (!pattern.empty()) {
			size_t insertPos = 0;
			if (body2.size() >= 2 && body2[0] == ILogger::COLOR_PREFIX) {
				insertPos = 2;
			}
			body2.insert(insertPos, formatPattern(pattern, category, level, time));
		}

		do_log_string(body2);
	}
}

void CommonLogger::set_pattern(const std::string &pattern) { this->pattern = pattern; }

void CommonLogger::enable_category(const std::string &category) { m_disabled_categories.erase(category); }

void CommonLogger::disable_category(const std::string &category) { m_disabled_categories.insert(category); }

void CommonLogger::set_max_level(Level level) { log_level = level; }

CommonLogger::CommonLogger(Level level) : log_level(level), pattern("%D %T %L [%C] ") {}

void CommonLogger::do_log_string(const std::string &message) {}
}
