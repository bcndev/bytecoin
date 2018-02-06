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


std::string getDefaultDataDirectory() {
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
	config_folder = [[paths
	objectAtIndex:
	0] UTF8String];

	return config_folder;
}

std::string get_app_data_folder(const std::string & app_name) {
	return getDefaultDataDirectory();
}

}
