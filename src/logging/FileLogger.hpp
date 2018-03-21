// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <mutex>
#include "CommonLogger.hpp"
#include "platform/Files.hpp"

namespace logging {

class FileLogger : public CommonLogger {
public:
	explicit FileLogger(const std::string &fullfilenamenoext, size_t max_size, Level level = DEBUGGING);

protected:
	virtual void do_log_string(const std::string &message) override;

private:
	std::mutex mutex;
	size_t max_size;
	const std::string fullfilenamenoext;
	std::unique_ptr<platform::FileStream> file_stream;
};
}
