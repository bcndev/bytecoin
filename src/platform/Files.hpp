// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string>
#include "common/Nocopy.hpp"
#include "common/Streams.hpp"

namespace platform {

class FileStream : public common::IOutputStream, public common::IInputStream, private common::Nocopy {
public:
	enum OpenMode {
		READ_EXISTING,
		READ_WRITE_EXISTING,
		TRUNCATE_READ_WRITE
	};  // to append, use READ_WRITE_EXISTING + seek(0, SEEK_END)
	explicit FileStream(const std::string &filename, OpenMode mode);
	~FileStream();
	size_t write_some(const void *data, size_t size) override;
	size_t read_some(void *data, size_t size) override;

	uint64_t seek(uint64_t pos, int whence);  // SEEK_SET, SEEK_CUR, SEEK_END
	uint64_t tellp() const { return const_cast<FileStream *>(this)->seek(0, SEEK_CUR); }
	void fsync();                  // top reason for existence of this class
	void truncate(uint64_t size);  // also sets pointer to the new end of file

#ifdef _WIN32
	static std::wstring utf8_to_utf16(const std::string &str);  // Used by various Windows API wrappers
	static std::string utf16_to_utf8(const std::wstring &str);  // Used by various Windows API wrappers
#endif
private:
	explicit FileStream();
	bool try_open(const std::string &filename, OpenMode mode);
	// We want those funs to use FileStream without exceptions (greatly hinders debugging)
	friend bool load_file(const std::string &filepath, std::string &buf);
	friend bool load_file(const std::string &filepath, common::BinaryArray &buf);
#ifdef _WIN32
	void *handle;  // HANDLE, cannot initialize hre because do not want to guess what is INVALID_HANDLE_VALUE
#else
	int fd = -1;
#endif
};
}
