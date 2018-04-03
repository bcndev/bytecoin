// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <functional>
#include <memory>
#include <string>
#include "common/Nocopy.hpp"
#include "common/Streams.hpp"

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#if defined(__ANDROID__)
#include <QTcpSocket>
#include <QTimer>

namespace platform {
class EventLoop {
public:
	static void cancel_current() {}
};
class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler a_handler);
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	void cancel();

private:
	after_handler a_handler;
	QTimer impl;
};

// socket is not RAII because it can go to disconnected state by external interaction
class TCPSocket : public common::IInputStream, public common::IOutputStream, private common::Nocopy {
public:
	typedef std::function<void(bool can_read, bool can_write)> RW_handler;
	typedef std::function<void(void)> D_handler;

	explicit TCPSocket(RW_handler rw_handler, D_handler d_handler);
	virtual ~TCPSocket() { close(); }
	void close();          // after close you are guaranteed that no handlers will be called
	bool is_open() const;  // Connecting or connected
	bool connect(const std::string &addr,
	    uint16_t port);  // either returns false or returns true and will call rw_handler or d_handler in future

	virtual size_t read_some(void *val, size_t count) override;
	// reads 0..count-1, if returns 0 (incoming buffer empty) would fire rw_handler or d_handler in future
	virtual size_t write_some(const void *val, size_t count) override;
	// writes 0..count-1, if returns 0 (outgoing buffer full) will fire rw_handler or d_handler in future
	void shutdown_both();  // will fire d_handler only after all sent data is acknowledged or disconnect happens
private:
	friend class TCPAcceptor;
	RW_handler rw_handler;
	D_handler d_handler;
	std::unique_ptr<QAbstractSocket> impl;
	bool ready = false;
};
class TCPAcceptor : private common::Nocopy {
public:
	typedef std::function<void()> A_handler;

	explicit TCPAcceptor(const std::string &addr,
	    uint16_t port,
	    A_handler a_handler,
	    const std::string &ssl_pem_file             = std::string(),
	    const std::string &ssl_certificate_password = std::string())
	    : a_handler(a_handler) {}
	~TCPAcceptor() {}

	bool accept(TCPSocket &socket, std::string &accepted_addr) { return false; }
	bool accept(TCPSocket &socket) { return false; }

private:
	A_handler a_handler;
};
}
#elif TARGET_OS_IPHONE
#include <CFNetwork/CFNetwork.h>
#include <CoreFoundation/CoreFoundation.h>

namespace platform {
class EventLoop {
public:
	static void cancel_current() {}
};
class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler a_handler) : a_handler(a_handler), impl(nullptr) {}
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	void cancel();

private:
	CFRunLoopTimerRef impl;
	static void static_once(CFRunLoopTimerRef impl, void *info);
	after_handler a_handler;
};

// socket is not RAII because it can go to disconnected state by external interaction
class TCPSocket : public common::IInputStream, public common::IOutputStream, private common::Nocopy {
public:
	typedef std::function<void(bool can_read, bool can_write)> RW_handler;
	typedef std::function<void(void)> D_handler;

	explicit TCPSocket(RW_handler rw_handler, D_handler d_handler) : rw_handler(rw_handler), d_handler(d_handler) {}
	virtual ~TCPSocket() { close(); }
	void close();          // after close you are guaranteed that no handlers will be called
	bool is_open() const;  // Connecting or connected
	bool connect(const std::string &addr, uint16_t port);
	// either returns false or returns true and will call rw_handler or d_handler in future

	virtual size_t read_some(void *val, size_t count) override;
	// reads 0..count-1, if returns 0 (incoming buffer empty) would fire rw_handler or d_handler in future
	virtual size_t write_some(const void *val, size_t count) override;
	// writes 0..count-1, if returns 0 (outgoing buffer full) will fire rw_handler or d_handler in future
	void shutdown_both();  // will fire d_handler only after all sent data is acknowledged or disconnect happens
private:
	friend class TCPAcceptor;
	RW_handler rw_handler;
	D_handler d_handler;
	CFReadStreamRef read_stream   = nullptr;
	CFWriteStreamRef write_stream = nullptr;
	void close_and_call();
	static void read_callback(CFReadStreamRef stream, CFStreamEventType event, void *my_ptr);
	static void write_callback(CFWriteStreamRef stream, CFStreamEventType event, void *my_ptr);
};
class TCPAcceptor : private common::Nocopy {
public:
	typedef std::function<void()> A_handler;

	explicit TCPAcceptor(const std::string &addr,
	    uint16_t port,
	    A_handler a_handler,
	    const std::string &ssl_pem_file             = std::string(),
	    const std::string &ssl_certificate_password = std::string())
	    : a_handler(a_handler) {}
	~TCPAcceptor() {}

	bool accept(TCPSocket &socket, std::string &accepted_addr) { return false; }
	bool accept(TCPSocket &socket) { return false; }

private:
	A_handler a_handler;
};
}
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <boost/asio.hpp>  // Drags windows.h, so bracketed by usual windows.h damage prevention
#ifdef _WIN32
#undef ERROR
#endif
namespace platform {
class EventLoop : private common::Nocopy {  // enough wrappers! if boost, use no impl at all...
public:
	explicit EventLoop(boost::asio::io_service &io_service);
	~EventLoop();

	static EventLoop *current() { return current_loop; }

	void run();  // run until cancel
	void cancel();
	void wake();

	static void cancel_current() { current()->cancel(); }

	boost::asio::io_service &io() { return io_service; }

private:
	boost::asio::io_service &io_service;
	static thread_local EventLoop *current_loop;
};

class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler a_handler) : a_handler(a_handler) {}
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	void cancel();

private:
	class Impl;
	std::shared_ptr<Impl> impl;  // Owned by boost async machinery
	after_handler a_handler;
};

// socket is not RAII because it can go to disconnected state by external interaction
class TCPSocket : public common::IInputStream, public common::IOutputStream, private common::Nocopy {
public:
	typedef std::function<void(bool can_read, bool can_write)> RW_handler;
	typedef std::function<void(void)> D_handler;

	explicit TCPSocket(RW_handler rw_handler, D_handler d_handler);
	virtual ~TCPSocket();
	void close();          // after close you are guaranteed that no handlers will be called
	bool is_open() const;  // Connecting or connected
	bool connect(const std::string &addr, uint16_t port);
	// either returns false or returns true and will call rw_handler or d_handler in future

	virtual size_t read_some(void *val, size_t count) override;
	// reads 0..count-1, if returns 0 (incoming buffer empty) would fire rw_handler or d_handler in future
	virtual size_t write_some(const void *val, size_t count) override;
	// writes 0..count-1, if returns 0 (outgoing buffer full) will fire rw_handler or d_handler in future
	void shutdown_both();  // will fire d_handler only after all sent data is acknowledged or disconnect happens
private:
	class Impl;
	std::shared_ptr<Impl> impl;  // Owned by boost async machinery

	friend class TCPAcceptor;
	RW_handler rw_handler;
	D_handler d_handler;
};

class TCPAcceptor : private common::Nocopy {
public:
	typedef std::function<void()> A_handler;

	explicit TCPAcceptor(const std::string &addr, uint16_t port, A_handler a_handler,
	    const std::string &ssl_pem_file = std::string(), const std::string &ssl_certificate_password = std::string());
	~TCPAcceptor();

	// if accept returns false, will fire accept_handler in future
	bool accept(TCPSocket &socket, std::string &accepted_addr);
	bool accept(TCPSocket &socket) {
		std::string a;
		return accept(socket, a);
	}

private:
	class Impl;
	std::shared_ptr<Impl> impl;  // Owned by boost async machinery
	A_handler a_handler;
};
}
#endif
