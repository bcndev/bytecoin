// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "IndexDB.hpp"
#include <string.h>
#include <iostream>
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/MemoryStreams.hpp"
#include "common/StringTools.hpp"
#include "common/string.hpp"

using namespace platform;

AsyncIndexDBOperation::AsyncIndexDBOperation(const std::string &full_name, O_handler o_handler) : o_handler(o_handler) {
	//	std::cout << "AsyncIndexDBOperation open " << full_name << std::endl;
	emscripten_fetch_attr_t attr;
	emscripten_fetch_attr_init(&attr);
	strcpy(attr.requestMethod, "GET");
	attr.attributes = EMSCRIPTEN_FETCH_NO_DOWNLOAD | EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
	attr.userData   = this;
	attr.onsuccess  = static_success;
	attr.onerror    = static_failed;
	fetch           = emscripten_fetch(&attr, full_name.c_str());
}

// Save
AsyncIndexDBOperation::AsyncIndexDBOperation(
    const std::string &full_name, const char *data, size_t size, S_handler s_handler)
    : s_handler(s_handler) {
	//	std::cout << "AsyncIndexDBOperation save " << full_name << std::endl;
	emscripten_fetch_attr_t attr;
	emscripten_fetch_attr_init(&attr);
	strcpy(attr.requestMethod, "EM_IDB_STORE");
	attr.attributes      = EMSCRIPTEN_FETCH_REPLACE | EMSCRIPTEN_FETCH_PERSIST_FILE;
	attr.requestData     = data;
	attr.requestDataSize = size;
	attr.userData        = this;
	attr.onsuccess       = static_success;
	attr.onerror         = static_failed;
	fetch                = emscripten_fetch(&attr, full_name.c_str());
}

AsyncIndexDBOperation::~AsyncIndexDBOperation() {
	//	std::cout << "~AsyncIndexDBOperation" << std::endl;
	cancel();
}

void AsyncIndexDBOperation::cancel() {
	//	std::cout << "AsyncIndexDBOperation::cancel" << std::endl;
	auto was_fetch = fetch;
	fetch          = nullptr;
	if (was_fetch)
		emscripten_fetch_close(was_fetch);
}

void AsyncIndexDBOperation::static_success(emscripten_fetch_t *fetch) {
	reinterpret_cast<AsyncIndexDBOperation *>(fetch->userData)->handle_result(fetch, true);
}

void AsyncIndexDBOperation::static_failed(emscripten_fetch_t *fetch) {
	reinterpret_cast<AsyncIndexDBOperation *>(fetch->userData)->handle_result(fetch, false);
}

void AsyncIndexDBOperation::handle_result(emscripten_fetch_t *was_fetch, bool success) {
	//	std::cout << "AsyncIndexDBOperation handle_result=" << int(success) << std::endl;
	if (fetch != was_fetch)
		return;  // on_error called from cancel
	fetch = nullptr;
	if (o_handler) {
		o_handler(success ? was_fetch->data : nullptr, success ? was_fetch->numBytes : 0);
		// here this might be deleted
	} else if (s_handler) {
		s_handler();
		// here this might be deleted
	}
	emscripten_fetch_close(was_fetch);
}
