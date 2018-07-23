// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "LoggerGroup.hpp"
#include <algorithm>

namespace logging {

LoggerGroup::LoggerGroup(Level level) : CommonLogger(level) {}

void LoggerGroup::add_logger(ILogger &logger) { loggers.push_back(&logger); }

void LoggerGroup::remove_logger(ILogger &logger) {
	loggers.erase(std::remove(loggers.begin(), loggers.end(), &logger), loggers.end());
}

void LoggerGroup::write(
    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) {
	if (level <= log_level && m_disabled_categories.count(category) == 0) {
		for (auto &logger : loggers) {
			logger->write(category, level, time, body);
		}
	}
}
}
