// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include <string>
#include <vector>

namespace http {

struct Header {
	std::string name;
	std::string value;
};

struct RequestHeader {
	std::string method;
	std::string uri;
	int http_version_major = 0;
	int http_version_minor = 0;

	std::vector<Header> headers;
	std::string basic_authorization;
	std::string host;
	std::string origin;

	bool keep_alive       = true;
	size_t content_length = std::numeric_limits<size_t>::max();

	void set_firstline(const std::string &m, const std::string &u, int ma, int mi) {
		method             = m;
		uri                = u;
		http_version_major = ma;
		http_version_minor = mi;
	}
	bool has_content_length() const { return content_length != size_t(-1); }
	std::string to_string() const;
};

struct ResponseHeader {
	int http_version_major = 0;
	int http_version_minor = 0;

	int status = 0;
	std::string status_text;
	std::vector<Header> headers;

	bool keep_alive       = true;
	size_t content_length = std::numeric_limits<size_t>::max();

	bool has_content_length() const { return content_length != size_t(-1); }

	std::string to_string() const;

	ResponseHeader() = default;
	explicit ResponseHeader(const RequestHeader &req)
	    : http_version_major(req.http_version_major)
	    , http_version_minor(req.http_version_minor)
	    , keep_alive(req.keep_alive) {}
	void add_headers_nocache() {
		headers.push_back(Header{"Cache-Control", "no-cache, no-store, must-revalidate"});
		headers.push_back(Header{"Expires", "0"});
	}
};

struct RequestBody {
	http::RequestHeader r;
	std::string body;

	void set_body(std::string &&b) {
		body             = std::move(b);
		r.content_length = body.size();
	}
};

struct ResponseBody {
	http::ResponseHeader r;
	std::string body;

	ResponseBody() = default;
	explicit ResponseBody(const http::RequestHeader &r) : r(r) {}
	void set_body(std::string &&b) {
		body             = std::move(b);
		r.content_length = body.size();
	}
};

bool is_char(int c);
bool is_ctl(int c);
bool is_tspecial(int c);
bool is_digit(int c);

std::string status_to_string(int status);

}  // namespace http
