// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "types.hpp"
#include <sstream>

namespace http {

/*struct mapping {
    const char *extension;
    const char *mime_type;
} const mappings[] = {
    {"gif", "image/gif"}, {"htm", "text/html"}, {"html", "text/html"}, {"jpg", "image/jpeg"}, {"png", "image/png"}};

std::string extension_to_mime_type(const std::string &extension) {
    for (auto &&m : mappings)
        if (m.extension == extension)
            return m.mime_type;
    return "text/plain";
}*/

struct smapping {
	int code;
	const char *text;
} const smappings[] = {{200, "OK"}, {400, "Bad request"}, {401, "Unauthorized"}, {403, "Forbidden"}, {404, "Not found"},
    {422, "Unprocessable Entity"}, {500, "Internal Error"}, {501, "Not implemented"},
    {502, "Service temporarily overloaded"}, {503, "Gateway timeout"}};

std::string status_to_string(int status) {
	for (auto m : smappings)
		if (m.code == status)
			return m.text;
	return "Unknown";
}

bool is_char(int c) { return c >= 0 && c <= 127; }

bool is_ctl(int c) { return (c >= 0 && c <= 31) || (c == 127); }

bool is_tspecial(int c) {
	switch (c) {
	case '(':
	case ')':
	case '<':
	case '>':
	case '@':
	case ',':
	case ';':
	case ':':
	case '\\':
	case '"':
	case '/':
	case '[':
	case ']':
	case '?':
	case '=':
	case '{':
	case '}':
	case ' ':
	case '\t':
		return true;
	default:
		return false;
	}
}

bool is_digit(int c) { return c >= '0' && c <= '9'; }

std::string request::to_string() const {
	std::stringstream ss;
	ss << method << " " << uri << " "
	   << "HTTP/" << http_version_major << "." << http_version_minor << "\r\n";
	if (!host.empty())
		ss << "Host: " << host << "\r\n";
	for (auto &&h : headers)
		ss << h.name << ": " << h.value << "\r\n";
	if (!basic_authorization.empty())
		ss << "Authorization: Basic " << basic_authorization << "\r\n";
	if (http_version_major == 1 && http_version_minor == 0 && keep_alive)
		ss << "Connection: keep-alive\r\n";
	if (has_content_length()) {
		ss << "Content-Length: " << content_length << "\r\n\r\n";
	} else
		ss << "\r\n";

	return ss.str();
}

std::string response::to_string() const {
	std::stringstream ss;
	ss << "HTTP/" << http_version_major << "." << http_version_minor << " " << status << " "
	   << (status_text.empty() ? status_to_string(status) : status_text) << "\r\n";
	for (auto &&h : headers)
		ss << h.name << ": " << h.value << "\r\n";
	if (http_version_major == 1 && http_version_minor == 0 && keep_alive)
		ss << "Connection: keep-alive\r\n";
	if (has_content_length()) {
		ss << "Content-Length: " << content_length << "\r\n\r\n";
	} else
		ss << "\r\n";

	return ss.str();
}

}  // namespace http
