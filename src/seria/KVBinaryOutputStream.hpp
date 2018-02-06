// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <vector>
#include "common/MemoryStreams.hpp"
#include "ISeria.hpp"

namespace seria {

class KVBinaryOutputStream : public ISeria {
public:
	explicit KVBinaryOutputStream(common::IOutputStream &target);
	virtual ~KVBinaryOutputStream() {}

	virtual bool isInput() const override { return false; }

	virtual void beginObject() override; // isMap forces saving keys even in binary serializer
	virtual void objectKey(common::StringView name) override;
	virtual void endObject() override;

	virtual void beginArray(size_t &size, bool fixed_size = false) override;
	virtual void endArray() override;

	virtual void beginMap(size_t &) override { beginObject(); }
	virtual void nextMapKey(std::string &name) override;
	virtual void endMap() override { endObject(); }

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
	void writeElementPrefix(uint8_t type);

	common::VectorStream &stream();

	enum class State {
		Root,
		Object,
		ArrayPrefix,
		Array
	};

	struct Level {
		std::string name;
		State state;
		size_t count;

		Level(common::StringView nm) :
				name(nm), state(State::Object), count(0) {}
		Level(common::StringView nm, size_t arraySize) :
				name(nm), state(State::ArrayPrefix), count(arraySize) {}
		Level(Level &&rv) {
			state = rv.state;
			name = std::move(rv.name);
			count = rv.count;
		}
	};

	bool expectingRoot = true;
	common::StringView nextKey;
	std::vector<common::VectorStream> m_objectsStack;
	std::vector<Level> m_stack;
	common::IOutputStream &target;
};

template<typename T>
common::BinaryArray toBinaryKeyValue(const T &v) {
	common::BinaryArray ba;
	common::VectorOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	s(const_cast<T &>(v));
	return ba;
}
template<typename T>
std::string toBinaryKeyValueStr(const T &v) {
	std::string ba;
	common::StringOutputStream stream(ba);
	KVBinaryOutputStream s(stream);
	s(const_cast<T &>(v));
	return ba;
}

}
