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

#include "ISeria.hpp"
#include "common/MemoryStreams.hpp"

namespace seria {

class BinaryInputStream : public ISeria {
public:
	BinaryInputStream(common::IInputStream &strm) : stream(strm) {}
	virtual ~BinaryInputStream() {}

	virtual bool isInput() const override { return true; }

	virtual void beginObject() override {}
	virtual void objectKey(common::StringView name) override {}
	virtual void endObject() override {}

	virtual void beginMap(size_t &size) override;
	virtual void nextMapKey(std::string &name) override;
	virtual void endMap() override {}

	virtual void beginArray(size_t &size, bool fixed_size = false) override;
	virtual void endArray() override {}

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
//	void checkedRead(char *buf, size_t size);
//	void checkedRead(unsigned char *buf, size_t size);
	common::IInputStream &stream;
};


template<typename T>
void fromBinary(T &obj, const common::BinaryArray &blob) {
	common::MemoryInputStream stream(blob.data(), blob.size());
	BinaryInputStream ba(stream);
	ba(obj);
}
template<typename T>
void fromBinary(T &obj, const std::string &blob) {
	common::MemoryInputStream stream(blob.data(), blob.size());
	BinaryInputStream ba(stream);
	ba(obj);
}
}
