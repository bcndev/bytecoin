// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include <string>
#include "Streams.hpp"
#include "common/BinaryArray.hpp"
#include "common/Nocopy.hpp"

namespace common {

class MemoryInputStream : public IInputStream {
public:
	MemoryInputStream(const void *buffer, size_t buffer_size);
	size_t size() const { return buffer_size - in_position; }
	bool empty() const { return size() == 0; }
	virtual size_t read_some(void *data, size_t size) override;

private:
	const char *buffer;
	size_t buffer_size;
	size_t in_position;
};

// Cannot be implemented with MemoryInputStream because string might be reallocated between reads (for rw stream)
class StringInputStream : public IInputStream, private common::Nocopy {
public:
	StringInputStream(const std::string &in) : in(&in), in_position(0) {}
	size_t read_some(void *data, size_t size) override;
	size_t size() const { return in->size() - in_position; }
	bool empty() const { return size() == 0; }
	size_t copy_to(IOutputStream &out, size_t max_count = std::numeric_limits<size_t>::max());

protected:
	const std::string *in;
	size_t in_position;
};

class StringOutputStream : public IOutputStream {
public:
	StringOutputStream(std::string &out) : out(&out) {}
	size_t write_some(const void *data, size_t size) override;

protected:
	std::string *out;
};

class StringStream : public StringInputStream, public StringOutputStream {
public:
	StringStream() : StringInputStream(m_buffer), StringOutputStream(m_buffer) {}
	explicit StringStream(const std::string &data)
	    : StringInputStream(m_buffer), StringOutputStream(m_buffer), m_buffer(data) {}
	explicit StringStream(std::string &&data)
	    : StringInputStream(m_buffer), StringOutputStream(m_buffer), m_buffer(std::move(data)) {}
	StringStream(StringStream &&other) noexcept
	    : StringInputStream(m_buffer), StringOutputStream(m_buffer), m_buffer(std::move(other.m_buffer)) {
		in_position = other.in_position;
	}
	StringStream &operator=(StringStream &&other) noexcept {
		m_buffer    = std::move(other.m_buffer);
		in          = &m_buffer;
		out         = &m_buffer;
		in_position = other.in_position;
		return *this;
	}

	std::string &buffer() { return m_buffer; }
	const std::string &buffer() const { return m_buffer; }

	void clear() {
		in_position = 0;
		m_buffer.clear();
	}

private:
	std::string m_buffer;
};

// Cannot be implemented with MemoryInputStream because string might be reallocated between reads (for rw stream)
class VectorInputStream : public IInputStream, private common::Nocopy {
public:
	VectorInputStream(const BinaryArray &in) : in(&in), in_position(0) {}

	size_t read_some(void *data, size_t size) override;
	size_t size() const { return in->size() - in_position; }
	bool empty() const { return size() == 0; }

	size_t copy_to(IOutputStream &out, size_t max_count = std::numeric_limits<size_t>::max());

protected:
	const BinaryArray *in;
	size_t in_position;
};

class VectorOutputStream : public IOutputStream {
public:
	explicit VectorOutputStream(BinaryArray &out) : out(&out) {}
	size_t write_some(const void *data, size_t size) override;

protected:
	BinaryArray *out;
};

class VectorStream : public VectorInputStream, public VectorOutputStream {
public:
	VectorStream() : VectorInputStream(m_buffer), VectorOutputStream(m_buffer) {}
	explicit VectorStream(const BinaryArray &data)
	    : VectorInputStream(m_buffer), VectorOutputStream(m_buffer), m_buffer(data) {}
	explicit VectorStream(BinaryArray &&data)
	    : VectorInputStream(m_buffer), VectorOutputStream(m_buffer), m_buffer(std::move(data)) {}
	VectorStream(VectorStream &&other) noexcept
	    : VectorInputStream(m_buffer), VectorOutputStream(m_buffer), m_buffer(std::move(other.m_buffer)) {
		in_position = other.in_position;
	}
	VectorStream &operator=(VectorStream &&other) noexcept {
		m_buffer    = std::move(other.m_buffer);
		in          = &m_buffer;
		out         = &m_buffer;
		in_position = other.in_position;
		return *this;
	}

	BinaryArray &buffer() { return m_buffer; }
	const BinaryArray &buffer() const { return m_buffer; }

	void clear() {
		in_position = 0;
		m_buffer.clear();
	}

private:
	BinaryArray m_buffer;
};

// Classic circular buffer
class CircularBuffer : public IInputStream, public IOutputStream {
	BinaryArray impl;
	size_t read_pos;   // 0..impl.size-1
	size_t write_pos;  // read_pos..read_pos + impl.size
public:
	explicit CircularBuffer(size_t si) : impl(si), read_pos(0), write_pos(0) {}
	virtual size_t read_some(void *data, size_t size) override;
	size_t size() const { return read_count() + read_count2(); }
	bool empty() const { return size() == 0; }

	virtual size_t write_some(const void *data, size_t size) override;
	size_t capacity() const { return write_count() + write_count2(); }
	bool full() const { return capacity() == 0; }

	void clear() { read_pos = write_pos = 0; }

	size_t read_count() const { return write_pos < impl.size() ? write_pos - read_pos : impl.size() - read_pos; }
	const unsigned char *read_ptr() const { return impl.data() + read_pos; }
	size_t write_count() const {
		return write_pos < impl.size() ? impl.size() - write_pos : read_pos - (write_pos - impl.size());
	}
	unsigned char *write_ptr() {
		return write_pos < impl.size() ? impl.data() + write_pos : impl.data() + write_pos - impl.size();
	}

	void did_write(size_t count);
	void did_read(size_t count);

	// circular buffer has maximum 2 parts. this gives second part
	size_t read_count2() const { return write_pos < impl.size() ? 0 : write_pos - impl.size(); }
	const unsigned char *read_ptr2() { return impl.data(); }
	size_t write_count2() const { return write_pos < impl.size() ? read_pos : 0; }
	unsigned char *write_ptr2() { return impl.data(); }

	void copy_from(IInputStream &in);
	size_t copy_to(IOutputStream &out, size_t max_count = std::numeric_limits<size_t>::max());
};
}
