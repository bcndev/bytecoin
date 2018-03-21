// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "ResponseParser.hpp"
#include <boost/lexical_cast.hpp>
#include <sstream>

using namespace http;

ResponseParser::ResponseParser() : state_(http_version_h) {}

void ResponseParser::reset() {
	state_  = http_version_h;
	lowcase = Header{};
}

ResponseParser::state ResponseParser::consume(response &req, char input) {
	switch (state_) {
	case http_version_h:
		if (input == 'H')
			return http_version_t_1;
		return bad;
	case http_version_t_1:
		if (input == 'T')
			return http_version_t_2;
		return bad;
	case http_version_t_2:
		if (input == 'T')
			return http_version_p;
		return bad;
	case http_version_p:
		if (input == 'P')
			return http_version_slash;
		return bad;
	case http_version_slash:
		if (input == '/')
			return http_version_major_start;
		return bad;
	case http_version_major_start:
		if (is_digit(input)) {
			req.http_version_major = req.http_version_major * 10 + input - '0';
			return http_version_major;
		}
		return bad;
	case http_version_major:
		if (input == '.')
			return http_version_minor_start;
		if (is_digit(input)) {
			req.http_version_major = req.http_version_major * 10 + input - '0';
			return http_version_major;
		}
		return bad;
	case http_version_minor_start:
		if (is_digit(input)) {
			req.http_version_minor = req.http_version_minor * 10 + input - '0';
			return http_version_minor;
		}
		return bad;
	case http_version_minor:
		if (input == ' ') {
			req.keep_alive = req.http_version_major == 1 && req.http_version_minor == 1;
			return status_code_1;
		}
		if (is_digit(input)) {
			req.http_version_minor = req.http_version_minor * 10 + input - '0';
			return http_version_minor;
		}
		return bad;
	case status_code_1:
		if (is_digit(input)) {
			req.status = req.status * 10 + input - '0';
			return status_code_2;
		}
		return bad;
	case status_code_2:
		if (is_digit(input)) {
			req.status = req.status * 10 + input - '0';
			return status_code_3;
		}
		return bad;
	case status_code_3:
		if (is_digit(input)) {
			req.status = req.status * 10 + input - '0';
			return status_code_space;
		}
		return bad;
	case status_code_space:
		if (input == ' ')
			return status_text;
		return bad;
	case status_text:
		if (input == '\r')
			return expecting_newline_1;
		if (is_ctl(input))
			return bad;
		req.status_text.push_back(input);
		return status_text;
	case expecting_newline_1:
		if (input == '\n') {
			req.headers.reserve(20);
			return header_line_start;
		}
		return bad;
	case header_line_start:
		if (input == '\r')
			return expecting_newline_3;
		if (!req.headers.empty() && (input == ' ' || input == '\t'))
			return header_lws;
		if (!is_char(input) || is_ctl(input) || is_tspecial(input))
			return bad;
		req.headers.push_back(Header{});
		req.headers.back().name.reserve(16);
		req.headers.back().value.reserve(16);
		req.headers.back().name.push_back(input);
		lowcase.name.push_back(tolower(input));
		return header_name;
	case header_lws:
		if (input == '\r')
			return expecting_newline_2;
		if (input == ' ' || input == '\t')
			return header_lws;
		if (is_ctl(input))
			return bad;
		req.headers.back().value.push_back(input);
		lowcase.value.push_back(tolower(input));
		return header_value;
	case header_name:
		if (input == ':')
			return space_before_header_value;
		if (!is_char(input) || is_ctl(input) || is_tspecial(input))
			return bad;
		req.headers.back().name.push_back(input);
		lowcase.name.push_back(tolower(input));
		return header_name;
	case space_before_header_value:
		if (input == ' ')
			return header_value;
		return bad;
	case header_value:
		if (input == '\r') {
			if (!process_ready_header(req))
				return bad;
			lowcase = Header{};
			return expecting_newline_2;
		}
		if (is_ctl(input))
			return bad;
		req.headers.back().value.push_back(input);
		lowcase.value.push_back(tolower(input));
		return header_value;
	case expecting_newline_2:
		if (input == '\n')
			return header_line_start;
		return bad;
	case expecting_newline_3:
		if (input == '\n')
			return good;
		return bad;
	default:
		return bad;
	}
}

bool ResponseParser::process_ready_header(response &req) {
	if (lowcase.name == "content-length") {
		try {
			req.content_length = boost::lexical_cast<decltype(req.content_length)>(lowcase.value);  // std::stoull
			req.headers.pop_back();
			return true;
		} catch (...) {
		}
		return false;
	}
	if (lowcase.name == "connection") {
		if (lowcase.value == "close") {
			req.keep_alive = false;
			req.headers.pop_back();
			return true;
		}
		if (lowcase.value == "keep-alive") {
			req.keep_alive = true;
			req.headers.pop_back();
			return true;
		}
		return false;
	}
	return true;
}
