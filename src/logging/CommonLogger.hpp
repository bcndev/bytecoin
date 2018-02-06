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

#include <set>
#include "ILogger.hpp"

namespace logging {

class CommonLogger : public ILogger {
public:

	virtual void operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) override;
	virtual void enable_category(const std::string &category);
	virtual void disable_category(const std::string &category);
	virtual void set_max_level(Level level);

	void set_pattern(const std::string &pattern);

protected:
	std::set<std::string> m_disabled_categories;
	Level logLevel;
	std::string pattern;

	CommonLogger(Level level);
	virtual void do_log_string(const std::string &message);
};

}
