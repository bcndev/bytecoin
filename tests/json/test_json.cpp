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

#include "test_json.hpp"

#include <cstddef>
#include <fstream>
#include <iomanip>
#include <ios>
#include <string>
#include <iostream>

#include "common/JsonValue.hpp"
#include "common/StringTools.hpp"

void test_json(const std::string & filename, bool should_be) {
	std::string content;
	if( !common::load_file(filename, content) )
		throw std::runtime_error("test file not found " + filename);
	bool success = false;
	try{
		common::JsonValue val = common::JsonValue::from_string(content);
		success = true;
	}catch(const std::exception & ex){
		std::cout << filename << " fail reason: " << ex.what() << std::endl;
	}
	if( success != should_be )
		throw std::runtime_error("test case failed " + filename);
}

void test_json(const std::string & test_vectors_folder) {
	for(int i = 1; i != 4; ++i)
		test_json(test_vectors_folder + "/pass" + std::to_string(i) + ".json", true);
	for(int i = 1; i != 34; ++i)
		test_json(test_vectors_folder + "/fail" + std::to_string(i) + ".json", i == 1 || i == 18);
	// We pass fail1 because we relax rules on top-level object or array
	// We pass fail18 because we support infinite depth of arrays
}

