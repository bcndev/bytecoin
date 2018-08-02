// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_json.hpp"

//#include <cstddef>
#include <fstream>
//#include <iomanip>
#include <iostream>

#include "common/JsonValue.hpp"
#include "platform/PathTools.hpp"

void test_json(const std::string &filename, bool should_be) {
	std::string content;
	if (!platform::load_file(filename, content))
		throw std::runtime_error("test file not found " + filename);
	bool success = false;
	try {
		common::JsonValue val = common::JsonValue::from_string(content);
		success               = true;
	} catch (const std::exception &) {
		//		std::cout << filename << " fail reason: " << ex.what() << std::endl;
	}
	if (success != should_be)
		throw std::runtime_error("test case failed " + filename);
}

void test_json(const std::string &test_vectors_folder) {
	for (int i = 1; i != 4; ++i)
		test_json(test_vectors_folder + "/pass" + std::to_string(i) + ".json", true);
	for (int i = 1; i != 34; ++i)
		test_json(test_vectors_folder + "/fail" + std::to_string(i) + ".json", i == 1 || i == 18);
	// We pass fail1 because we relax rules on top-level object or array
	// We pass fail18 because we support infinite depth of arrays
}
