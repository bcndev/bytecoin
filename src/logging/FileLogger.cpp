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

#include "platform/PathTools.hpp"
#include "FileLogger.hpp"

namespace logging {

FileLogger::FileLogger(const std::string &fullfilenamenoext, size_t max_size, Level level)
		: CommonLogger(level), max_size(max_size), fullfilenamenoext(fullfilenamenoext)
{
	try {
		fileStream = std::make_unique<platform::FileStream>(this->fullfilenamenoext + "_0.log",
															platform::FileStream::READ_WRITE_EXISTING);
		fileStream->seek(0, SEEK_END);
	}catch(const std::exception &){
		fileStream = std::make_unique<platform::FileStream>(this->fullfilenamenoext + "_0.log",
															platform::FileStream::TRUNCATE_READ_WRITE);
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
		if (fileStream)
			fileStream->write(real_message.data(), real_message.size());
	} catch (...) { // Will continue trying to write when space becomes available
	}

	if (fileStream && fileStream->tellp() >= max_size) {
		std::string cur = fullfilenamenoext + "_0.log";
		std::string prev = fullfilenamenoext + "_1.log";
		if (!platform::atomic_replace_file(cur, prev)) {
			//StreamLogger::doLogString("FileLogger failed to rotate log file, doubling size of next rotation...");
			max_size *= 2;
			return;
		}
		try {
			fileStream = std::make_unique<platform::FileStream>(cur, platform::FileStream::TRUNCATE_READ_WRITE);
		} catch (...) { // Will continue using old one if new one fails to open
		}
	}
}


}
