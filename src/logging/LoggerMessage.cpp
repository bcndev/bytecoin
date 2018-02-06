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

#include "LoggerMessage.hpp"

namespace logging {

LoggerMessage::LoggerMessage(ILogger &logger, const std::string &category, Level level)
		: std::ostream(this), logger(logger), category(category), logLevel(level),
		timestamp(boost::posix_time::microsec_clock::local_time()) {
//	(*this) << std::string{ILogger::COLOR_PREFIX, static_cast<char>(ILogger::COLOR_LETTER_DEFAULT + color)};
//	(*this) << color;
}

LoggerMessage::~LoggerMessage() {
	if( !str().empty() )
		(*this) << std::endl;
}

LoggerMessage::LoggerMessage(LoggerMessage&& other)
  : std::ostream(this)
  , logger(other.logger)
  , category(other.category)
  , logLevel(other.logLevel)
  , timestamp(boost::posix_time::microsec_clock::local_time()) {
	(*this) << other.str();
	other.str(std::string());
}

int LoggerMessage::sync() {
	logger(category, logLevel, timestamp, str());
	str(std::string());
	return 0;
}

}
