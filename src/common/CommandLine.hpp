// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstring>
#include <typeinfo>
#include <vector>

namespace common {

class CommandLine {  // Lean command line parsing. Best! :)
	struct SView {   // Micro String View
		explicit SView(const char *data) : data(data), size(strlen(data)) {}
		explicit SView(const char *data, size_t size) : data(data), size(size) {}
		int compare(const SView &other) const;
		const char *data;
		size_t size;
	};
	struct Option {
		explicit Option(SView key) : key(key) {}
		SView key;
		std::vector<const char *> values;
		bool used                      = false;
		bool in_help                   = false;
		const char *wrong_type_message = nullptr;

		bool operator<(const Option &other) const { return key.compare(other.key) < 0; }
	};
	Option *find_option(const SView &key);
	std::vector<Option> options;
	std::vector<const char *> positional;
	bool positional_used = false;

public:
	CommandLine(int argc, const char *const argv[]);
	CommandLine() = default;  // Sometimes usefull in test code
	// call show_help right after constructor
	// help will be parsed so that show errors will print different text for
	// unused options found in help (wrong context) and not found in help (typo)
	bool show_help(const char *help_text, const char *version_text = nullptr);
	// gets are non-const because they mark used options and remember wrong types
	const char *get(const char *key, const char *deprecation_text = nullptr);
	bool get_bool(const char *key, const char *deprecation_text = nullptr);
	const std::type_info &get_type(const char *key);  // nullptr_t, bool, const char *, std::vector<const char *>
	const std::vector<const char *> &get_array(const char *key, const char *deprecation_text = nullptr);
	const std::vector<const char *> &get_positional(const char *deprecation_text = nullptr);
	// after everything is parsed call this fun to quit if there were errors
	// context can be specified for better error text
	bool show_errors(const char *context = nullptr);

	static int toy_main(int argc, const char *argv[]);  // For testing
};
}  // namespace common
