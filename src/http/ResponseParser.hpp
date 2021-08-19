// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "types.hpp"

namespace http {

struct ResponseHeader;

class ResponseParser {
	enum state {
		http_version_h,
		http_version_t_1,
		http_version_t_2,
		http_version_p,
		http_version_slash,
		http_version_major_start,
		http_version_major,
		http_version_minor_start,
		http_version_minor,
		status_code_1,
		status_code_2,
		status_code_3,
		status_code_space,
		status_text,
		expecting_newline_1,
		header_line_start,
		header_lws,
		header_name,
		space_before_header_value,
		header_value,
		expecting_newline_2,
		expecting_newline_3,
		good,
		bad
	} state_;

public:
	ResponseParser();

	void reset();

	template<typename InputIterator>
	InputIterator parse(ResponseHeader &req, InputIterator begin, InputIterator end) {
		while (begin != end && state_ != good && state_ != bad)
			state_ = consume(req, *begin++);
		return begin;
	}
	bool is_good() const { return state_ == good; }
	bool is_bad() const { return state_ == bad; }

private:
	bool process_ready_header(ResponseHeader &req);
	Header lowcase;
	state consume(ResponseHeader &req, char input);
};

}  // namespace http
