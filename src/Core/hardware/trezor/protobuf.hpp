#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace protobuf {

typedef std::string::const_iterator iterator;

inline uint64_t read_varint(iterator *s, iterator e) {
	size_t read       = 0;
	const size_t bits = 64;
	uint64_t result   = 0;
	for (size_t shift = 0;; shift += 7) {
		if (*s == e)
			throw std::runtime_error("varint end of input");
		unsigned char byte = *(*s)++;
		++read;
		if (shift + 7 >= bits && byte >= 1 << (bits - shift))
			throw std::runtime_error("varint 64-bit overflow");
		if (byte == 0 && shift != 0)
			throw std::runtime_error("varint non-canonical rep");
		result |= static_cast<uint64_t>(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0)
			break;
	}
	return result;
}
template<class T>
inline T read_varint_t(iterator *s, iterator e) {
	return static_cast<T>(read_varint(s, e));
}
inline void write_varint(uint64_t v, std::string &s) {
	while (v >= 0x80) {
		s.push_back(static_cast<char>((v & 0x7f) | 0x80));
		v >>= 7;
	}
	s.push_back(static_cast<char>(v));
}

inline uint64_t zigzag(int64_t val) { return val >= 0 ? uint64_t(val) << 1 : (uint64_t(-(val + 1)) << 1) | 1; }

inline int64_t zagzig(uint64_t val) { return (val & 1) ? -int64_t(val >> 1) - 1 : int64_t(val >> 1); }

inline iterator skip(iterator *s, iterator e, size_t len) {
	size_t remains = static_cast<size_t>(e - *s);
	if (remains < len)
		throw std::runtime_error("protobuf skip underflow");
	iterator result = *s;
	*s += len;
	return result;
}

inline std::string read_string(iterator *s, iterator e) {
	auto len = read_varint_t<size_t>(s, e);
	auto p   = skip(s, e, len);
	std::string str{p, *s};
	return str;
}

inline void write_field_varint(unsigned field_number, uint64_t v, std::string &s) {
	write_varint((field_number << 3) | 0, s);
	write_varint(v, s);
}

inline void write_field_string(unsigned field_number, const std::string &v, std::string &s) {
	write_varint((field_number << 3) | 2, s);
	write_varint(v.size(), s);
	s += v;
}

inline void write_field_fixed32(unsigned field_number, const void *v, std::string &s) {
	write_varint((field_number << 3) | 5, s);
	s.append(reinterpret_cast<const char *>(v), 4);
}

inline void write_field_fixed64(unsigned field_number, const void *v, std::string &s) {
	write_varint((field_number << 3) | 1, s);
	s.append(reinterpret_cast<const char *>(v), 8);
}

template<class T>
inline T read_fixed(iterator *s, iterator e) {
	auto p = skip(s, e, sizeof(T));
	T val;
	memcpy(&val, &*p, sizeof(T));
	return val;
}

inline void skip_by_type(unsigned field_type, iterator *s, iterator e) {
	switch (field_type) {
	case 0:
		read_varint(s, e);
		break;
	case 1:  // 64-bit fixed
		skip(s, e, 8);
		break;
	case 2: {
		auto len = read_varint_t<size_t>(s, e);
		skip(s, e, len);
		break;
	}
	case 3:  // start group
	case 4:  // end group
		throw std::runtime_error("groups are not supported");
	case 5:
		skip(s, e, 4);
		break;
	default:
		break;
	}
}

template<typename T>
void read_message(T &v, iterator *s, iterator e) {
	auto len = read_varint_t<size_t>(s, e);
	auto p   = skip(s, e, len);
	read(v, p, *s);
}

template<typename T>
void read_packed_varint(std::vector<T> &v, iterator *s, iterator e) {
	auto len = read_varint_t<size_t>(s, e);
	auto p   = skip(s, e, len);
	while (p != *s) {
		v.push_back(read_varint_t<T>(&p, *s));
	}
}

template<typename T>
void read_packed_s_varint(std::vector<T> &v, iterator *s, iterator e) {
	auto len = read_varint_t<size_t>(s, e);
	auto p   = skip(s, e, len);
	while (p != *s) {
		v.push_back(static_cast<T>(zagzig(read_varint(&p, *s))));
	}
}
template<typename T>
void write_packed_varint(unsigned field_number, const std::vector<T> &v, std::string &s) {
	if (v.empty())
		return;
	std::string pack;
	for (const auto &vv : v)
		write_varint(static_cast<uint64_t>(vv), pack);
	write_field_string(field_number, pack, s);
}
template<typename T>
void write_packed_s_varint(unsigned field_number, const std::vector<T> &v, std::string &s) {
	if (v.empty())
		return;
	std::string pack;
	for (const auto &vv : v)
		write_varint(zigzag(vv), pack);
	write_field_string(field_number, pack, s);
}
template<typename T>
void write_packed_fixed(unsigned field_number, const std::vector<T> &v, std::string &s) {
	if (v.empty())
		return;
	write_varint((field_number << 3) | 2, s);
	write_varint(v.size() * sizeof(T), s);
	s.append(reinterpret_cast<const char *>(v.data()), v.size() * sizeof(T));
}

template<typename T>
void read_packed_fixed(std::vector<T> &v, iterator *s, iterator e) {
	auto len = read_varint_t<size_t>(s, e);
	auto p   = skip(s, e, len);
	if (len % sizeof(T) != 0)
		throw std::runtime_error("packed fixed field has uneven size");
	auto count = len / sizeof(T);
	v.resize(v.size() + count);
	memcpy(v.data() + v.size() - count, &*p, len);
}

}  // namespace protobuf
