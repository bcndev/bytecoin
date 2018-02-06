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

#pragma once

#include <vector>
#include <cstring>
#include <typeinfo>

namespace common {

class CommandLine { // Lean command line parsing. Best! :)
	struct SView { // Micro String View
		explicit SView(const char *data): data(data), size(strlen(data)) {}
		explicit SView(const char *data, size_t size): data(data), size(size) {}
		int compare(const SView &other) const;
		const char *data;
		size_t size;
	};
	struct Option {
		explicit Option(SView key): key(key) {}
		SView key;
		std::vector<const char *> values;
		bool used = false;
		const char *wrong_type_message = nullptr;
		
		bool operator<(const Option &other) const { return key.compare(other.key) < 0; }
	};
	Option *find_option(const SView &key);
	std::vector<Option> options;
	const std::vector<const char *> empty_array; // we return & from get_array
	std::vector<const char *> positional;
	bool positional_used = false;
public:
	CommandLine(int argc, const char *argv[]);
	// gets are non-const because they mark used options and remember wrong types
	const char * get(const char *key, const char *deprecation_text = nullptr);
	bool get_bool(const char *key, const char *deprecation_text = nullptr);
	const std::type_info & get_type(const char *key); // nullptr_t, bool, const char *, std::vector<const char *>
	const std::vector<const char *> &get_array(const char *key, const char *deprecation_text = nullptr);
	const std::vector<const char *> &get_positional(const char *deprecation_text = nullptr);
	// after everything is parsed call this fun to quit if there were errors or help, version was specified
	bool should_quit(const char *help_text = nullptr, const char *version_text = nullptr);

	static int toy_main(int argc, const char *argv[]); // For testing
};

}
