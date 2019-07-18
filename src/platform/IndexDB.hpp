// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <map>
#include <string>
#include "common/Nocopy.hpp"

#include <emscripten/fetch.h>

namespace platform {

class AsyncIndexDBOperation {
public:
	typedef std::function<void(const char *data, size_t size)> O_handler;
	typedef std::function<void()> S_handler;
	// Open
	AsyncIndexDBOperation(const std::string &full_name, O_handler o_handler);
	// Save
	AsyncIndexDBOperation(const std::string &full_name, const char *data, size_t size, S_handler s_handler);
	~AsyncIndexDBOperation();
	void cancel();

private:
	static void static_success(emscripten_fetch_t *fetch);
	static void static_failed(emscripten_fetch_t *fetch);
	void handle_result(emscripten_fetch_t *was_fetch, bool success);
	emscripten_fetch_t *fetch = nullptr;
	O_handler o_handler;
	S_handler s_handler;
};

}  // namespace platform
