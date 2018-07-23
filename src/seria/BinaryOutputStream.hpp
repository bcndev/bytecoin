// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class BinaryOutputStream : public ISeria {
public:
	BinaryOutputStream(common::IOutputStream &strm) : stream(strm) {}
	virtual ~BinaryOutputStream() {}

	virtual bool is_input() const override { return false; }

	virtual void begin_object() override {}
	virtual void object_key(common::StringView, bool optional = false) override {}
	virtual void end_object() override {}

	virtual void begin_array(size_t &size, bool fixed_size = false) override;
	virtual void end_array() override {}

	virtual void begin_map(size_t &size) override;
	virtual void next_map_key(std::string &name) override;
	virtual void end_map() override {}

	virtual void seria_v(uint8_t &value) override;
	virtual void seria_v(int16_t &value) override;
	virtual void seria_v(uint16_t &value) override;
	virtual void seria_v(int32_t &value) override;
	virtual void seria_v(uint32_t &value) override;
	virtual void seria_v(int64_t &value) override;
	virtual void seria_v(uint64_t &value) override;
	virtual void seria_v(double &value) override;
	virtual void seria_v(bool &value) override;
	virtual void seria_v(std::string &value) override;
	virtual void seria_v(common::BinaryArray &value) override;
	virtual void binary(void *value, size_t size) override;

private:
	common::IOutputStream &stream;
};

template<typename T>
common::BinaryArray to_binary(const T &obj) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ba(const_cast<T &>(obj));
	return result;
}
template<typename T>
std::string to_binary_str(const T &obj) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	std::string result;
	common::StringOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ba(const_cast<T &>(obj));
	return result;
}
template<typename T>
size_t binary_size(const T &obj) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::BinaryArray result;
	common::VectorOutputStream stream(result);
	BinaryOutputStream ba(stream);
	ba(const_cast<T &>(obj));
	return result.size();
}
}
