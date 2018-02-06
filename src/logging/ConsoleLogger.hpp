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

#include <mutex>
#include "CommonLogger.hpp"

namespace logging {

class ConsoleLogger : public CommonLogger {
public:
	ConsoleLogger(Level level = DEBUGGING);

protected:
	virtual void do_log_string(const std::string &message) override;

private:
	static std::mutex mutex; // we can have 2 console loggers, for WalletNode and Node
};

}
