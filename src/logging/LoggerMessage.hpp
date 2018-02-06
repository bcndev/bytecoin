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

#include <iostream>
#include "ILogger.hpp"
#include "common/Nocopy.hpp"

namespace logging {

class LoggerMessage : public std::ostream, private std::stringbuf, private common::Nocopy {
public:
	LoggerMessage(ILogger &logger, const std::string &category, Level level);
	~LoggerMessage();
	LoggerMessage(LoggerMessage &&other);
private:
	int sync() override;

	ILogger &logger;
	const std::string category;
	Level logLevel;
	boost::posix_time::ptime timestamp;
};

class LoggerRef {
public:
	LoggerRef(ILogger &logger, const std::string &category) : logger(&logger), category(category) {
	}
//	LoggerMessage operator()(Level level, const Color &color) const {
//		return LoggerMessage(*logger, category, level, color);
//	}
	LoggerMessage operator()(Level level) const {
		return LoggerMessage(*logger, category, level);
	}
	LoggerMessage operator()() const {
		return (*this)(INFO);
	}
	ILogger &get_logger() const{ return *logger; }
private:
	ILogger *logger;
	std::string category;
};

}
