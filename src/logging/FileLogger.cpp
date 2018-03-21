// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "FileLogger.hpp"
#include "platform/PathTools.hpp"

namespace logging {

FileLogger::FileLogger(const std::string &fullfilenamenoext, size_t max_size, Level level)
    : CommonLogger(level), max_size(max_size), fullfilenamenoext(fullfilenamenoext) {
	try {
		file_stream = std::make_unique<platform::FileStream>(
		    this->fullfilenamenoext + "_0.log", platform::FileStream::READ_WRITE_EXISTING);
		file_stream->seek(0, SEEK_END);
	} catch (const std::exception &) {
		file_stream = std::make_unique<platform::FileStream>(
		    this->fullfilenamenoext + "_0.log", platform::FileStream::TRUNCATE_READ_WRITE);
	}
}

void FileLogger::do_log_string(const std::string &message) {
	std::lock_guard<std::mutex> lock(mutex);
	std::string real_message;
	real_message.reserve(message.size());

	for (size_t charPos = 0; charPos < message.size(); ++charPos) {
		if (message[charPos] == ILogger::COLOR_PREFIX) {
			charPos += 1;
		} else {
			real_message += message[charPos];
		}
	}
	try {
		if (file_stream)
			file_stream->write(real_message.data(), real_message.size());
	} catch (...) {  // Will continue trying to write when space becomes available
	}

	if (file_stream && file_stream->tellp() >= max_size) {
		std::string cur  = fullfilenamenoext + "_0.log";
		std::string prev = fullfilenamenoext + "_1.log";
		if (!platform::atomic_replace_file(cur, prev)) {
			// StreamLogger::doLogString("FileLogger failed to rotate log file, doubling size of next rotation...");
			max_size *= 2;
			return;
		}
		try {
			file_stream = std::make_unique<platform::FileStream>(cur, platform::FileStream::TRUNCATE_READ_WRITE);
		} catch (...) {  // Will continue using old one if new one fails to open
		}
	}
}
}
