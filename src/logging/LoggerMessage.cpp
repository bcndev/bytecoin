// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "LoggerMessage.hpp"

namespace logging {

LoggerMessage::LoggerMessage(ILogger &logger, const std::string &category, Level level)
    : std::ostream(this)
    , logger(logger)
    , category(category)
    , log_level(level)
    , timestamp(boost::posix_time::microsec_clock::local_time()) {
	//	(*this) << std::string{ILogger::COLOR_PREFIX, static_cast<char>(ILogger::COLOR_LETTER_DEFAULT + color)};
	//	(*this) << color;
}

LoggerMessage::~LoggerMessage() {
	if (!str().empty())
		(*this) << std::endl;
}

LoggerMessage::LoggerMessage(LoggerMessage &&other)
    : std::ostream(this)
    , logger(other.logger)
    , category(other.category)
    , log_level(other.log_level)
    , timestamp(boost::posix_time::microsec_clock::local_time()) {
	(*this) << other.str();
	other.str(std::string());
}

int LoggerMessage::sync() {
	logger.write(category, log_level, timestamp, str());
	str(std::string());
	return 0;
}
}
