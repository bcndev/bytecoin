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
#include <boost/algorithm/string/trim.hpp>


namespace platform {

std::string get_os_version_string() {
	return "iOS :)"; // TODO
}


std::string get_default_data_directory() {
	//namespace fs = boost::filesystem;
	// Windows < Vista: C:\Documents and Settings\Username\Application Data\CRYPTONOTE_NAME
	// Windows >= Vista: C:\Users\Username\AppData\Roaming\CRYPTONOTE_NAME
	// Mac: ~/Library/Application Support/CRYPTONOTE_NAME
	// Unix: ~/.CRYPTONOTE_NAME
	std::string config_folder;

	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	//NSString *documentsDirectory = [paths objectAtIndex:0];    NSArray * paths = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask];
	//NSURL * documentsURL = [paths lastObject];
	//config_folder = [[documentsURL absoluteString] UTF8String];
	config_folder = [[paths	objectAtIndex:0] UTF8String];

	return config_folder;
}

std::string get_app_data_folder(const std::string & app_name) {
	return get_default_data_directory();
}

}
