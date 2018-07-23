// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Files.hpp"
#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <ios>
#include <stdexcept>
#include "common/string.hpp"
#ifdef _WIN32
#include "platform/Windows.hpp"
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace platform;

FileStream::FileStream() {
#ifdef _WIN32
	handle = INVALID_HANDLE_VALUE;
#endif
}

FileStream::FileStream(const std::string &filename, OpenMode mode) {
#ifdef _WIN32
	handle = INVALID_HANDLE_VALUE;
#endif
	if (!try_open(filename, mode))
		throw common::StreamError("File failed to open " + filename);
}

FileStream::~FileStream() {
#ifdef _WIN32
	CloseHandle(handle);
	handle = INVALID_HANDLE_VALUE;
#else
	close(fd);
	fd = -1;
#endif
}

bool FileStream::try_open(const std::string &filename, OpenMode mode) {
#ifdef _WIN32
	CloseHandle(handle);
	handle = INVALID_HANDLE_VALUE;

	auto wfilename = utf8_to_utf16(filename);
	handle         = CreateFileW(wfilename.c_str(), GENERIC_READ | (mode == READ_EXISTING ? 0 : GENERIC_WRITE),
	    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
	    (mode == TRUNCATE_READ_WRITE) ? CREATE_ALWAYS : (mode == READ_WRITE_EXISTING) ? OPEN_EXISTING : OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, nullptr);
	DWORD err = GetLastError();
	return handle != INVALID_HANDLE_VALUE;
#else
	close(fd);
	fd = -1;

	int m1 = (mode == TRUNCATE_READ_WRITE) ? (O_CREAT | O_TRUNC) : (mode == READ_WRITE_EXISTING) ? 0 : 0;
	fd     = open(filename.c_str(), m1 | (mode == READ_EXISTING ? O_RDONLY : O_RDWR), 0600);
	return fd != -1;
#endif
}

uint64_t FileStream::seek(uint64_t pos, int whence) {
#ifdef _WIN32
	LARGE_INTEGER lpos{}, rpos{};
	lpos.QuadPart = pos;
	static_assert(SEEK_END == FILE_END && SEEK_CUR == FILE_CURRENT && SEEK_SET == FILE_BEGIN,
	    "Whene definition between Windows and POSIX do not match");
	if (!SetFilePointerEx(handle, lpos, &rpos, whence))
		throw common::StreamError("Error seeking file in seek, GetLastError=" + common::to_string(GetLastError()));
	return rpos.QuadPart;
#else
	off_t res = lseek(fd, pos, whence);
	if (res == -1)
		throw common::StreamError("Error seeking file in seek, errno=" + common::to_string(errno));
	return res;
#endif
}
static const size_t MAX_CHUNK = 1024 * 1024 * 1024;
size_t FileStream::write_some(const void *data, size_t size) {
	size = std::min(size, MAX_CHUNK);  // Some oses cannot write more than 2 gb at once
#ifdef _WIN32
	DWORD si = 0;
	if (!WriteFile(handle, data, static_cast<DWORD>(size), &si, nullptr))
		throw common::StreamError("Error writing file, GetLastError()=" + common::to_string(GetLastError()));
	return si;
#else
	size_t si = ::write(fd, data, size);
	if (si == (size_t)-1)
		throw common::StreamError("Error writing file, errno=" + common::to_string(errno));
	return si;
#endif
}
size_t FileStream::read_some(void *data, size_t size) {
	size = std::min(size, MAX_CHUNK);  // Some oses cannot read more than 2 gb at once
#ifdef _WIN32
	DWORD si = 0;
	if (!ReadFile(handle, data, static_cast<DWORD>(size), &si, nullptr))
		throw common::StreamError("Error reading file, GetLastError()=" + common::to_string(GetLastError()));
	return si;
#else
	size_t si = ::read(fd, data, size);
	if (si == (size_t)-1)
		throw common::StreamError("Error reading file, errno=" + common::to_string(errno));
	return si;
#endif
}

void FileStream::fsync() {
#ifdef _WIN32
	if (!FlushFileBuffers(handle))
		throw common::StreamError("Error syncing file to disk, GetLastError()=" + common::to_string(GetLastError()));
#else
	if (::fsync(fd) == -1)
		throw common::StreamError("Error syncing file to disk, errno=" + common::to_string(errno));
#endif
}

void FileStream::truncate(uint64_t size) {
	seek(size, SEEK_SET);  // Required only on Windows, but we make behavior consistent between platforms
#ifdef _WIN32
	if (!SetEndOfFile(handle))
		throw common::StreamError("Error truncating file on disk, GetLastError()=" + common::to_string(GetLastError()));
#else
	if (::ftruncate(fd, size) == -1)
		throw common::StreamError("Error truncating file on disk, errno=" + common::to_string(errno));
#endif
}

#ifdef _WIN32
std::wstring FileStream::utf8_to_utf16(const std::string &str) {
	std::wstring result;
	result.resize(str.size() * 2);  // str.size should be enough, but who knows
	auto si = MultiByteToWideChar(CP_UTF8, 0, str.data(), boost::lexical_cast<int>(str.size()), &result[0],
	    boost::lexical_cast<int>(result.size()));
	result.resize(si);
	return result;
}

std::string FileStream::utf16_to_utf8(const std::wstring &str) {
	std::string result;
	result.resize(str.size() * 5);  // str.size*4 should be enough, but who knows
	auto si = WideCharToMultiByte(CP_UTF8, 0, str.data(), boost::lexical_cast<int>(str.size()), &result[0],
	    boost::lexical_cast<int>(result.size()), nullptr, nullptr);
	result.resize(si);
	return result;
}

#endif
