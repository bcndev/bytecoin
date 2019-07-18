// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#import <Foundation/Foundation.h>

#include "PathTools.hpp"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <streambuf>
#include "common/StringTools.hpp"
#include "CryptoNoteConfig.hpp"

#include <sys/utsname.h>
#include <sys/stat.h>

namespace platform {

#if TARGET_OS_IPHONE
std::string get_os_version_string() {
	return "iOS";
}
std::string get_platform_name() {
	return "iOS";
}
std::string get_app_data_folder(const std::string & app_name) {
	std::string config_folder;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	//NSString *documentsDirectory = [paths objectAtIndex:0];    NSArray * paths = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask];
	//NSURL * documentsURL = [paths lastObject];
	//config_folder = [[documentsURL absoluteString] UTF8String];
	config_folder = [[paths	objectAtIndex:0] UTF8String];

	return config_folder;
}
#endif

#if TARGET_OS_OSX
std::string get_os_version_string() {
	auto str = [[NSProcessInfo processInfo] operatingSystemVersionString];
	return "macOS " + std::string([str UTF8String]);
}
std::string get_platform_name() {
	return "darwin";
}
std::string get_app_data_folder(const std::string & app_name) {
	std::string config_folder;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
	return normalize_folder([[paths	objectAtIndex:0] UTF8String]) + "/" + app_name;
}
#endif

}
