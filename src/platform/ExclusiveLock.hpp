// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>
#include <string>

namespace platform {

class ExclusiveLock {
public:
	class FailedToLock : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};
	explicit ExclusiveLock(const std::string &folder, const std::string &file);
	~ExclusiveLock();

private:
#ifdef _WIN32
	void *handle = nullptr;
#else
	int fd = 0;
#endif
};
}  // namespace platform
