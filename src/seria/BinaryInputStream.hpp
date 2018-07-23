// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <typeinfo>
#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class BinaryInputStream : public ISeria {
public:
	BinaryInputStream(common::IInputStream &strm) : stream(strm) {}
	virtual ~BinaryInputStream() {}

	virtual bool is_input() const override { return true; }

	virtual void begin_object() override {}
	virtual void object_key(common::StringView, bool optional = false) override {}
	virtual void end_object() override {}

	virtual void begin_map(size_t &size) override;
	virtual void next_map_key(std::string &name) override;
	virtual void end_map() override {}

	virtual void begin_array(size_t &size, bool fixed_size = false) override;
	virtual void end_array() override {}

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
	common::IInputStream &stream;
};

template<typename T>
void from_binary(T &obj, const common::BinaryArray &blob) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::MemoryInputStream stream(blob.data(), blob.size());
	BinaryInputStream ba(stream);
	ba(obj);
	if (!stream.empty())
		throw std::runtime_error("Excess data in from_binary " + std::string(typeid(T).name()));
}
template<typename T>
void from_binary(T &obj, const std::string &blob) {
	static_assert(!std::is_pointer<T>::value, "Cannot be called with pointer");
	common::MemoryInputStream stream(blob.data(), blob.size());
	BinaryInputStream ba(stream);
	ba(obj);
	if (!stream.empty())
		throw std::runtime_error("Excess data in from_binary " + std::string(typeid(T).name()));
}
}
