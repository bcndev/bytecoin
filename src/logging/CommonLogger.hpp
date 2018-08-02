// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <set>
#include "ILogger.hpp"

namespace logging {

class CommonLogger : public ILogger {
public:
	virtual void write(
	    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) override;
	virtual void enable_category(const std::string &category);
	virtual void disable_category(const std::string &category);
	virtual void set_max_level(Level level);

	void set_pattern(const std::string &pattern);

protected:
	std::set<std::string> m_disabled_categories;
	Level log_level;
	std::string pattern;

	CommonLogger(Level level);
	virtual void do_log_string(const std::string &message);
};
}
