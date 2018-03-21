// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

namespace http {

struct Header {
	std::string name;
	std::string value;
};

struct request {
	std::string method;
	std::string uri;
	int http_version_major = 0;
	int http_version_minor = 0;

	std::vector<Header> headers;
	std::string basic_authorization;
	std::string host;

	bool keep_alive       = true;
	size_t content_length = -1;

	void set_firstline(
	    const std::string &method, const std::string &uri, int http_version_major, int http_version_minor) {
		this->method             = method;
		this->uri                = uri;
		this->http_version_major = http_version_major;
		this->http_version_minor = http_version_minor;
	}
	bool has_content_length() const { return content_length != size_t(-1); }
	std::string to_string() const;
};

struct response {
	int http_version_major = 0;
	int http_version_minor = 0;

	int status = 0;
	std::string status_text;
	std::vector<Header> headers;

	bool keep_alive       = true;
	size_t content_length = -1;

	bool has_content_length() const { return content_length != size_t(-1); }

	std::string to_string() const;

	response() {}
	explicit response(const request &req)
	    : http_version_major(req.http_version_major)
	    , http_version_minor(req.http_version_minor)
	    , keep_alive(req.keep_alive) {}
	void add_headers_nocache() {
		headers.push_back(Header{"Cache-Control", "no-cache, no-store, must-revalidate"});
		headers.push_back(Header{"Expires", "0"});
	}
};

struct RequestData {
	http::request r;
	std::string body;

	void set_body(std::string &&body) {
		this->body       = std::move(body);
		r.content_length = this->body.size();
	}
};

struct ResponseData {
	http::response r;
	std::string body;

	ResponseData() {}
	explicit ResponseData(const http::request &r) : r(r) {}
	void set_body(std::string &&body) {
		this->body       = std::move(body);
		r.content_length = this->body.size();
	}
};

bool is_char(int c);
bool is_ctl(int c);
bool is_tspecial(int c);
bool is_digit(int c);

std::string status_to_string(int status);
// std::string extension_to_mime_type(const std::string &extension);

}  // namespace http
