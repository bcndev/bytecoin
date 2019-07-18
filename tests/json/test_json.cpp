// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "test_json.hpp"

//#include <cstddef>
#include <fstream>
#include <iostream>
#include "common/Invariant.hpp"
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
		//		std::cout << filename << " fail reason: " << common::what(ex) <<
		// std::endl;
	}
	if (success != should_be)
		throw std::runtime_error("test case failed " + filename);
}

static std::map<std::string, uint64_t> cases1{
    {"20000000000000000000000000000000E-31", 2U},
    {"0.000000000000000000000000000000003E33", 3U},
    {"-0.00E1024", 0U},
    {"0.00E-1024", 0U},
    {"92233720368547758060.00E-1", 9223372036854775806U},
    {"922337203685477580.6E1", 9223372036854775806U},
    {"184467440737095516150E-1", 18446744073709551615U},
    {"1844674407370955161.5E1", 18446744073709551615U},

    {"0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001811234E206",
        1811234},
};

static std::map<std::string, int64_t> cases2{
    {"20000000000000000000000000000000E-31", 2},
    {"-20000000000000000000000000000000.0E-31", -2},
    {"-0.00E1024", 0},
    {"0.00E-1024", 0},
    {"0.000000000000000000000000000000003E33", 3},
    {"-92233720368547758070.00E-1", -9223372036854775807},
    {"-922337203685477580.7E1", -9223372036854775807},
    {"0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001811234E206",
        1811234},
};

void test_json(const std::string &test_vectors_folder) {
	for (const auto &ca : cases1) {
		common::JsonValue jv;
		jv.set_number(ca.first);
		invariant(jv.get_unsigned() == ca.second, "");
	}
	for (const auto &ca : cases2) {
		common::JsonValue jv;
		jv.set_number(ca.first);
		invariant(jv.get_integer() == ca.second, "");
	}

	for (int i = 1; i != 4; ++i)
		test_json(test_vectors_folder + "/pass" + std::to_string(i) + ".json", true);
	for (int i = 1; i != 35; ++i)
		test_json(test_vectors_folder + "/fail" + std::to_string(i) + ".json", i == 1);
	// We pass fail1 because we relax rules on top-level object or array
}
