// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

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
	Level log_level;
	boost::posix_time::ptime timestamp;
};

class LoggerRef {
public:
	LoggerRef(ILogger &logger, const std::string &category) : logger(&logger), category(category) {}
	LoggerMessage operator()(Level level) const { return LoggerMessage(*logger, category, level); }
	LoggerMessage operator()() const { return (*this)(INFO); }
	ILogger &get_logger() const { return *logger; }

private:
	ILogger *logger;
	std::string category;
};
}
