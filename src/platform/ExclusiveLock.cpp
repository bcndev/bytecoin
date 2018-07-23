// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "ExclusiveLock.hpp"
#include <stdexcept>
#include "Files.hpp"
#include "PathTools.hpp"

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#ifdef _WIN32
#include "platform/Windows.hpp"
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace platform;
ExclusiveLock::ExclusiveLock(const std::string &folder, const std::string &file) {
	std::string full_path = folder + "/" + file;
#if !TARGET_OS_IPHONE  // We do not need lock on iOS because only 1 instance of app will be running
//	create_folders_if_necessary(folder);  // We ignore result here
#ifdef _WIN32
	auto wfull_path = FileStream::utf8_to_utf16(full_path);
	handle = CreateFileW(wfull_path.c_str(), GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE)
#else
	fd         = open(full_path.c_str(), O_CREAT | O_WRONLY, 0600);
	int status = lockf(fd, F_TLOCK, 4096);
	if (status != 0)
#endif
		throw FailedToLock("ExclusiveLock fail at path=" + full_path);
#endif
}

ExclusiveLock::~ExclusiveLock() {
#if !TARGET_OS_IPHONE
#ifdef _WIN32
	CloseHandle(handle);
	handle = nullptr;
#else
	close(fd);
	fd = 0;
#endif
// We make no attempt do delete lockfile, because we will most likely be killed by Ctrl-C
#endif
}
