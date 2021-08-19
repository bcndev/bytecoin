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

#ifdef __EMSCRIPTEN__
namespace platform {
class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler &&a_handler);
	~Timer();

	void once(float after_seconds);  // cancels previous once first
	bool is_set() const;
	void cancel();

private:
	class Impl;
	std::unique_ptr<Impl> impl;
	after_handler a_handler;
};

}  // namespace platform
#elif platform_USE_QT
#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <atomic>

namespace platform {
class EventLoop {
	//    Q_OBJECT
	// public:
	//	EventLoop();
	//	~EventLoop();
	//	static EventLoop *current() { return current_loop; }
	//	static void cancel_current() {}
	// private:
	//	static thread_local EventLoop *current_loop;
};
class SafeMessage;
// Nested classes cannot have slots
class SafeMessageImpl : public QObject {
	Q_OBJECT
public:
	explicit SafeMessageImpl(SafeMessage *owner);
	~SafeMessageImpl();
	platform::SafeMessage *owner;
	std::atomic<int> counter;

	void close();
public slots:
	void handle_event();
};
class SafeMessage : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit SafeMessage(after_handler &&a_handler);
	~SafeMessage();

	void fire();  // The only method to be called from other threads
	void cancel();

private:
	friend class SafeMessageImpl;
	std::unique_ptr<SafeMessageImpl> impl;
	after_handler a_handler;
};
class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler a_handler);
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	bool is_set() const;
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
	class AddressInUse : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};

	typedef std::function<void()> A_handler;

	explicit TCPAcceptor(const std::string &addr, uint16_t port, A_handler a_handler) : a_handler(a_handler) {}
	~TCPAcceptor() {}

	bool accept(TCPSocket &socket, std::string &accepted_addr) { return false; }
	bool accept(TCPSocket &socket) { return false; }

private:
	A_handler a_handler;
};
}  // namespace platform
#elif TARGET_OS_IPHONE
#include <CFNetwork/CFNetwork.h>
#include <CoreFoundation/CoreFoundation.h>

namespace platform {
class EventLoop {
public:
	static void cancel_current() {}
	static EventLoop *current() { return nullptr; }
	void wake(std::function<void()> &&a_handler) {}
};
class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler &&a_handler) : a_handler(std::move(a_handler)), impl(nullptr) {}
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	bool is_set() const;
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

	explicit TCPSocket(RW_handler &&rw_handler, D_handler &&d_handler)
	    : rw_handler(std::move(rw_handler)), d_handler(std::move(d_handler)) {}
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

	explicit TCPAcceptor(const std::string &addr, uint16_t port, A_handler &&a_handler)
	    : a_handler(std::move(a_handler)) {}
	~TCPAcceptor() {}

	bool accept(TCPSocket &socket, std::string &accepted_addr) { return false; }
	bool accept(TCPSocket &socket) { return false; }

private:
	A_handler a_handler;
};
class UDPMulticast : private common::Nocopy {
public:
	typedef std::function<void(const std::string &addr, const unsigned char *data, size_t size)> P_handler;
	UDPMulticast(const std::string &addr, uint16_t port, P_handler &&p_handler) : p_handler(std::move(p_handler)) {}
	~UDPMulticast() {}
	static void send(const std::string &addr, uint16_t port, const void *data, size_t size) {}

private:
	P_handler p_handler;
};
}  // namespace platform
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
	void wake(std::function<void()> &&a_handler);

	static void cancel_current() { current()->cancel(); }

	boost::asio::io_service &io() { return io_service; }

private:
	boost::asio::io_service &io_service;
	static thread_local EventLoop *current_loop;
};
class SafeMessage : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit SafeMessage(after_handler &&a_handler);
	~SafeMessage();

	void fire();  // The only method to be called from other threads
	void cancel();

private:
	class Impl;
	std::unique_ptr<Impl> impl;
	after_handler a_handler;
};

class Timer : private common::Nocopy {
public:
	typedef std::function<void()> after_handler;

	explicit Timer(after_handler &&a_handler) : a_handler(std::move(a_handler)) {}
	~Timer() { cancel(); }

	void once(float after_seconds);  // cancels previous once first
	bool is_set() const;
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

	explicit TCPSocket(RW_handler &&rw_handler, D_handler &&d_handler);
	~TCPSocket() override;
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
	class AddressInUse : public std::runtime_error {
	public:
		using std::runtime_error::runtime_error;
	};

	static std::vector<std::string> local_addresses(bool ipv4, bool ipv6);

	explicit TCPAcceptor(const std::string &addr, uint16_t port, A_handler &&a_handler);
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

// Experimental zero-config for finding local peers (good for testnets)
class UDPMulticast : private common::Nocopy {
public:
	typedef std::function<void(const std::string &addr, const unsigned char *data, size_t size)> P_handler;
	UDPMulticast(const std::string &addr, uint16_t port, P_handler &&p_handler);
	~UDPMulticast();
	static void send(const std::string &addr, uint16_t port, const void *data, size_t size);  // simple synchronous send
private:
	class Impl;
	std::shared_ptr<Impl> impl;  // Owned by boost async machinery
	P_handler p_handler;
};
}  // namespace platform
#endif
