// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "FileLogger.hpp"
#include "platform/PathTools.hpp"

namespace logging {

FileLogger::FileLogger(const std::string &fullfilenamenoext, size_t max_size, Level level)
    : CommonLogger(level), initial_max_size(max_size), max_size(max_size), fullfilenamenoext(fullfilenamenoext) {
	try {
		file_stream = std::make_unique<platform::FileStream>(
		    this->fullfilenamenoext + ".log", platform::FileStream::READ_WRITE_EXISTING);
		file_stream->seek(0, SEEK_END);
	} catch (const std::exception &) {
		file_stream = std::make_unique<platform::FileStream>(
		    this->fullfilenamenoext + ".log", platform::FileStream::TRUNCATE_READ_WRITE);
	}
}

void FileLogger::do_log_string(const std::string &message) {
	std::lock_guard<std::mutex> lock(mutex);
	std::string real_message;
	real_message.reserve(message.size());

	for (size_t char_pos = 0; char_pos < message.size(); ++char_pos) {
		if (message[char_pos] == ILogger::COLOR_PREFIX) {
			char_pos += 1;
		} else {
			real_message += message[char_pos];
		}
	}
	try {
		if (file_stream)
			file_stream->write(real_message.data(), real_message.size());
	} catch (...) {  // Will continue trying to write when space becomes available
	}

	if (file_stream && file_stream->tellp() >= max_size) {
		std::string cur  = fullfilenamenoext + ".log";
		std::string prev = fullfilenamenoext + "_prev.log";
		if (!using_prev && !platform::atomic_replace_file(cur, prev)) {
			// StreamLogger::do_log_string("FileLogger failed to rotate log file, doubling size of next rotation...");
			max_size *= 2;
			return;
		}
		try {
			file_stream = std::make_unique<platform::FileStream>(cur, platform::FileStream::TRUNCATE_READ_WRITE);
			using_prev  = false;
			max_size    = initial_max_size;
		} catch (...) {  // Will continue using old one if new one fails to open
			using_prev = true;
			max_size *= 2;  // doubling size of next rotation...
		}
	}
}
}
