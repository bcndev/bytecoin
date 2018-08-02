// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "CommandLine.hpp"
#include <stdio.h>
#include <algorithm>

// no std::string - no std::cout, printf is synced with it anyway

using namespace common;

static const std::vector<const char *> empty_array;  // we return & from get_array

// We use ordering optimized for speed, as any ordering is good for us
int CommandLine::SView::compare(const SView &other) const {
	if (size != other.size)
		return int(size) - int(other.size);
	return memcmp(data, other.data, size);
}

CommandLine::CommandLine(int argc, const char *const argv[]) {
	if (argc < 1)
		return;
	bool positional_only = false;
	std::vector<Option> flat_options;  // first gather all options
	flat_options.reserve(argc - 1);
	for (int i = 1; i != argc; ++i) {
		if (argv[i][0] != '-' || positional_only) {
			positional.push_back(argv[i]);
			continue;
		}
		if (argv[i][1] == '-' && argv[i][2] == 0) {  // After -- all args are positional
			positional_only = true;
			continue;
		}
		const char *eqpos = strchr(argv[i], '=');
		Option option(eqpos ? SView(argv[i], eqpos - argv[i]) : SView(argv[i]));
		if (eqpos)
			option.values.push_back(eqpos + 1);
		else
			option.values.push_back(nullptr);  // nullptr indicates flag
		flat_options.push_back(option);
	}
	std::sort(flat_options.begin(), flat_options.end());  // Then sort
	options.reserve(flat_options.size());
	for (auto &&it : flat_options) {
		if (options.empty() || options.back().key.compare(it.key) != 0)
			options.push_back(it);
		else
			options.back().values.push_back(it.values.front());
	}
}

CommandLine::Option *CommandLine::find_option(const SView &key) {
	Option search_option(key);
	auto vit = std::lower_bound(options.begin(), options.end(), search_option);
	return vit != options.end() && vit->key.compare(key) == 0 ? &*vit : nullptr;
}

// gets are non-const because they mark used options
const char *CommandLine::get(const char *key, const char *deprecation_text) {
	Option *op = find_option(SView(key));
	if (!op)
		return nullptr;
	op->used = true;
	if (op->values.size() != 1 && !op->wrong_type_message)
		op->wrong_type_message = "should not be specified more than once";
	if (!op->values.front() && !op->wrong_type_message)
		op->wrong_type_message = "is not flag and should have value (use --<option>=<value>)";
	if (deprecation_text)
		printf("Command line option %s is deprecated. %s\n", key, deprecation_text);
	return op->values.front() ? op->values.front() : nullptr;
}

bool CommandLine::get_bool(const char *key, const char *deprecation_text) {
	Option *op = find_option(SView(key));
	if (!op)
		return false;
	op->used = true;
	if (op->values.size() != 1 && !op->wrong_type_message)
		op->wrong_type_message = "should not be specified more than once";
	if (op->values.front() && !op->wrong_type_message)
		op->wrong_type_message = "is flag and should not have value (use --<option>, not --<option>=<value>)";
	if (deprecation_text)
		printf("Command line option %s is deprecated. %s\n", key, deprecation_text);
	return !op->values.front();  // if value set, bool flag is not specified
}

const std::type_info &CommandLine::get_type(const char *key) {
	Option *op = find_option(SView(key));
	if (!op)
		return typeid(std::nullptr_t);
	if (op->values.size() != 1)
		return typeid(std::vector<const char *>);  // array
	if (op->values.front())
		return typeid(const char *);  // string
	return typeid(bool);
}

const std::vector<const char *> &CommandLine::get_array(const char *key, const char *deprecation_text) {
	Option *op = find_option(SView(key));
	if (!op)
		return empty_array;
	op->used = true;
	for (auto vit = op->values.begin(); vit != op->values.end();)
		if (!*vit) {
			if (!op->wrong_type_message)
				op->wrong_type_message = "is not flag and should have value (use --<option>=<value>)";
			vit = op->values.erase(vit);  // After recording wrong type, we fix it so clients will not crash
		} else
			++vit;
	if (deprecation_text)
		printf("Command line option %s is deprecated. %s\n", key, deprecation_text);
	return op->values;
}
const std::vector<const char *> &CommandLine::get_positional(const char *deprecation_text) {
	positional_used = true;
	if (deprecation_text)
		printf("Positional command line options are deprecated. %s\n", deprecation_text);
	return positional;
}

bool CommandLine::should_quit(const char *help_text, const char *version_text) {
	const bool v1 = get_bool("--version");
	const bool v2 = get_bool("-v");
	if (version_text && (v1 || v2)) {  // in case both specified
		printf("%s\n", version_text);
		return true;  // No more output so scripts get version only
	}
	bool quit     = false;
	const bool h1 = get_bool("--help");
	const bool h2 = get_bool("-h");
	if (help_text && (h1 || h2)) {  // in case both specified
		printf("%s\n", help_text);
		quit = true;
	}
	if (!positional_used)
		for (auto &&po : positional) {
			printf("Positional args are not allowed - you specified '%s' (typo?)\n", po);
			quit = true;
		}
	for (auto &&op : options) {
		if (!op.used) {
			printf("Command line option %s has no meaning (typo?)\n", op.key.data);
			quit = true;
		}
		if (op.wrong_type_message) {
			printf("Command line option %s %s\n", op.key.data, op.wrong_type_message);
			quit = true;
		}
	}
	return quit;
}

static const char TOY_USAGE[] =
    R"(toy <version>.

Usage:
  toy [options]
  toy -h | --help
  toy -v | --version
Options:
  -h --help            Show this screen.
  -v --version         Show version.
  --bool               Bool (flag)
  --pos                Specify to make toy get positional args
  --str=<str>          String
  --array=<el>         Array
  --deprecated=<str>   Deprecated string
)";

int CommandLine::toy_main(int argc, const char *argv[]) {
	common::CommandLine cmd(argc, argv);
	if (const char *pa = cmd.get("--str"))
		printf("--str={%s}\n", pa);
	if (const char *pa = cmd.get("--deprecated", "Use --str instead"))
		printf("--deprecated={%s}\n", pa);
	if (cmd.get_bool("--bool"))
		printf("--bool set\n");
	for (auto &&el : cmd.get_array("--array"))
		printf("--array value={%s}\n", el);
	if (cmd.get_bool("--pos"))
		for (auto &&el : cmd.get_positional())
			printf("positional value={%s}\n", el);
	if (cmd.should_quit(TOY_USAGE, "Toy cmd v 1.1"))
		return 0;
	printf("Toy is launching...\n");
	return 0;
}
