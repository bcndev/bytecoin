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

#include <list>
#include <memory>
#include <mutex>
#include "common/JsonValue.hpp"
#include "LoggerGroup.hpp"
#include "LoggerMessage.hpp"

namespace logging {

class LoggerManager : public LoggerGroup {
public:
	LoggerManager();
	void configure_default(const std::string &log_folder, const std::string &log_prefix); // log_folder must exist
	void configure(const common::JsonValue &val);
	virtual void operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) override;

private:
	std::vector<std::unique_ptr<CommonLogger>> loggers;
	std::mutex reconfigureLock;
};

}
