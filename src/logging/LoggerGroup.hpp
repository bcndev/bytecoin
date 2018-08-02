// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <vector>
#include "CommonLogger.hpp"

namespace logging {

class LoggerGroup : public CommonLogger {
public:
	explicit LoggerGroup(Level level = TRACE);

	void add_logger(ILogger &logger);
	void remove_logger(ILogger &logger);
	virtual void write(
	    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) override;

protected:
	std::vector<ILogger *> loggers;
};
}
