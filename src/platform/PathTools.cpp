// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "PathTools.hpp"
#include <algorithm>
#include <cstdio>
#include <sstream>
#include "Files.hpp"
#include "common/Math.hpp"

#ifdef _WIN32
#include <shlobj.h>
#include <strsafe.h>
#include "platform/Windows.hpp"
#pragma warning(disable : 4996)  // Deprecated GetVersionA
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <boost/algorithm/string/trim.hpp>

#endif

#ifdef __ANDROID__
#include <QStandardPaths>
#endif

namespace platform {
#ifdef __ANDROID__
std::string get_os_version_string() { return "Android"; }
std::string get_app_data_folder(const std::string &app_name) {
	QString data_path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
	return data_path.toStdString();
}
#elif defined(_WIN32)
std::string get_os_version_string() {
	typedef void(WINAPI * PGNSI)(LPSYSTEM_INFO);
	typedef BOOL(WINAPI * PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

	std::ostringstream stream;

	OSVERSIONINFOEX osvi{};
	SYSTEM_INFO si{};

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (!GetVersionExA(reinterpret_cast<OSVERSIONINFO *>(&osvi))) {
		stream << "Microsoft Windows, GetVersionExA failed";
		return stream.str();
	}

	PGNSI pGNSI = (PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if (pGNSI)
		pGNSI(&si);
	else
		GetSystemInfo(&si);

	stream << "Microsoft Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "." << osvi.wProductType
	       << ", wSuiteMask=" << osvi.wSuiteMask << ", build " << osvi.dwBuildNumber;
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		stream << ", 64-bit";
	else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		stream << ", 32-bit";
	else
		stream << ", wProcessorArchitecture=" << si.wProcessorArchitecture;
	if (osvi.dwPlatformId != VER_PLATFORM_WIN32_NT)
		stream << ", dwPlatformId=" << osvi.dwPlatformId;
	PGPI pGPI = (PGPI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
	if (pGPI) {
		DWORD dwType = 0;
		pGPI(osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);
		stream << ", Edition=" << dwType;
	}

	if (strlen(osvi.szCSDVersion) > 0)
		stream << " " << osvi.szCSDVersion;

	return stream.str();
}
static std::string get_special_folder_path(int nfolder, bool iscreate) {
	wchar_t psz_path[MAX_PATH]{};
	if (SHGetSpecialFolderPathW(NULL, psz_path, nfolder, iscreate)) {
		return FileStream::utf16_to_utf8(psz_path);
	}
	return std::string();
}
std::string get_platform_name() { return sizeof(size_t) == 4 ? "windows(32bit)" : "windows"; }
std::string get_app_data_folder(const std::string &app_name) {
	return get_special_folder_path(CSIDL_APPDATA, true) + "\\" + app_name;
}
#else
static std::string get_home_folder() {
	std::string path_ret;
	const char *psz_home = getenv("HOME");
	if (psz_home)
		path_ret = normalize_folder(psz_home);
	return path_ret;
}
#if !TARGET_OS_MAC
std::string get_os_version_string() {
	utsname un;

	if (uname(&un) < 0)
		return std::string("*nix: failed to get os version");
	return std::string() + un.sysname + " " + un.version + " " + un.release;
}
std::string get_platform_name() {
#if defined(__linux__)
	return "linux";
#else
	return "UNIX";
#endif
}
std::string get_app_data_folder(const std::string &app_name) {
	std::string path_ret;
	const char *psz_home = getenv("HOME");
	if (psz_home)
		path_ret = normalize_folder(psz_home);
	return get_home_folder() + "/." + app_name;
}
#endif
#endif

bool folder_exists(const std::string &path) {
#if defined(_WIN32)
	auto wsubpath  = FileStream::utf8_to_utf16(expand_path(path));
	DWORD dwAttrib = GetFileAttributesW(wsubpath.c_str());

	return dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
#else
	struct stat info;

	if (stat(expand_path(path).c_str(), &info) != 0)
		return false;  // printf( "cannot access %s\n", pathname );
	if (info.st_mode & S_IFDIR)
		return true;
	return false;
#endif
}

std::string normalize_folder(const std::string &path) {
	std::string result = path;
#if defined(_WIN32)
	while (result.size() > 0 && (result.back() == '/' || result.back() == '\\'))
		result.pop_back();
#else
	while (result.size() > 0 && result.back() == '/')
		result.pop_back();
#endif
	return result;
}

std::string expand_path(const std::string &path) {
#ifdef __ANDROID__
	return path;
#elif defined(_WIN32)
	if (path.compare(0, sizeof("%appdata%") - 1, "%appdata%") == 0)
		return get_special_folder_path(CSIDL_APPDATA, true) + path.substr(9);
#else
	if (!path.empty() && path[0] == '~')
		return get_home_folder() + path.substr(1);
#endif
	return path;
}

bool create_folder_if_necessary(const std::string &subpath) {
#if defined(_WIN32)
	auto wsubpath = FileStream::utf8_to_utf16(expand_path(subpath));
	DWORD last    = 0;
	if (CreateDirectoryW(wsubpath.c_str(), nullptr) == 0 && (last = GetLastError()) != ERROR_ALREADY_EXISTS)
		return false;
	return true;
#else
	mode_t mode = 0755;
	if (mkdir(expand_path(subpath).c_str(), mode) != 0 && errno != EEXIST)
		return false;
	return true;
#endif
}

std::string get_filename_without_folder(const std::string &path) {
	size_t delim1 = path.rfind("/");
#if defined(_WIN32)
	size_t delim2 = path.rfind("\\");
#else
	size_t delim2    = std::string::npos;
#endif
	size_t delim_pos =
	    delim1 == std::string::npos ? delim2 : delim2 == std::string::npos ? delim1 : std::max(delim1, delim2);
	return delim_pos != std::string::npos ? path.substr(delim_pos + 1) : path;
}

bool create_folders_if_necessary(const std::string &path) {
#if defined(_WIN32)
	size_t delim_pos = std::min(path.find("/"), path.find("\\"));
#else
	size_t delim_pos = path.find("/");
#endif
	while (delim_pos != std::string::npos) {
		create_folder_if_necessary(
		    path.substr(0, delim_pos + 1));  // We ignore intermediate results, because of some systems
#if defined(_WIN32)
		delim_pos = std::min(path.find("/", delim_pos + 1), path.find("\\", delim_pos + 1));
#else
		delim_pos = path.find("/", delim_pos + 1);
#endif
	}
	return create_folder_if_necessary(path);
}

bool atomic_replace_file(const std::string &from_path, const std::string &to_path) {
#if defined(_WIN32)
	auto wfrom_path = FileStream::utf8_to_utf16(expand_path(from_path));
	auto wto_path   = FileStream::utf8_to_utf16(expand_path(to_path));
	// Maximizing chances for success
	DWORD attributes = GetFileAttributesW(wto_path.c_str());
	if (INVALID_FILE_ATTRIBUTES != attributes)
		SetFileAttributesW(wto_path.c_str(), attributes & (~FILE_ATTRIBUTE_READONLY));
	bool ok = MoveFileExW(wfrom_path.c_str(), wto_path.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
// int code = ok ? 0 : static_cast<int>(::GetLastError());
#else
	bool ok = std::rename(expand_path(from_path).c_str(), expand_path(to_path).c_str()) == 0;
// int code = ok ? 0 : errno;
#endif
	// if(err) *err = std::error_code(code, std::system_category());
	return ok;
}
bool copy_file(const std::string &from_path, const std::string &to_path) {
	platform::FileStream from(from_path, platform::O_READ_EXISTING);
	platform::FileStream to(to_path, platform::O_CREATE_ALWAYS);
	auto si = from.seek(0, SEEK_END);
	from.seek(0, SEEK_SET);
	while (si > 0) {
		const uint64_t CHUNK = 10 * 1024 * 1024;
		common::BinaryArray data(static_cast<size_t>(std::min(si, CHUNK)));
		from.read(data.data(), data.size());
		to.write(data.data(), data.size());
		si -= data.size();
	}
	return true;
}

bool remove_file(const std::string &path) {
#if defined(_WIN32)
	auto wpath = FileStream::utf8_to_utf16(expand_path(path));
	return DeleteFileW(wpath.c_str()) != 0;
#else
	return std::remove(expand_path(path).c_str()) == 0;
#endif
}

std::vector<std::string> get_filenames_in_folder(const std::string &path) {
	std::vector<std::string> result;
#if defined(_WIN32)
	auto wpath = FileStream::utf8_to_utf16(expand_path(path) + "/*.*");
	WIN32_FIND_DATAW fd;
	HANDLE hFind = ::FindFirstFileW(wpath.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				result.push_back(FileStream::utf16_to_utf8(fd.cFileName));
			}
		} while (::FindNextFileW(hFind, &fd));
		::FindClose(hFind);
	}
#else
	DIR *dir = opendir(expand_path(path).c_str());
	if (dir) {
		while (struct dirent *ent = readdir(dir)) {  // != nullptr
			std::string name = ent->d_name;
			if (!name.empty() && name.at(0) != '.')
				result.push_back(name);
		}
		closedir(dir);
		dir = nullptr;
	}
#endif
	return result;
}

bool load_file(const std::string &filepath, std::string &buf) {
	try {
		FileStream fs;  // Allowed because we are friends
		if (!fs.try_open(filepath, O_READ_EXISTING))
			return false;
		size_t file_size = common::integer_cast<size_t>(fs.seek(0, SEEK_END));
		fs.seek(0, SEEK_SET);
		buf.resize(file_size);
		fs.read(&buf[0], buf.size());
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

bool load_file(const std::string &filepath, common::BinaryArray &buf) {
	try {
		FileStream fs;  // Allowed because we are friends
		if (!fs.try_open(filepath, O_READ_EXISTING))
			return false;
		size_t file_size = common::integer_cast<size_t>(fs.seek(0, SEEK_END));
		fs.seek(0, SEEK_SET);
		buf.resize(file_size);
		fs.read(buf.data(), buf.size());
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

bool save_file(const std::string &filepath, const void *buf, size_t size) {
	try {
		FileStream fs(filepath, platform::O_CREATE_ALWAYS);
		fs.write(buf, size);
	} catch (const std::exception &) {
		return false;
	}
	return true;
}
bool atomic_save_file(const std::string &filepath, const void *buf, size_t size, const std::string &tmp_filepath) {
	try {
		FileStream fs(tmp_filepath, platform::O_CREATE_ALWAYS);
		fs.write(buf, size);
		fs.fsync();
	} catch (const std::exception &) {
		return false;
	}
	return atomic_replace_file(tmp_filepath, filepath);
}
}  // namespace platform
