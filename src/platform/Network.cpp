#include "Network.hpp"
#include "common/MemoryStreams.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib") // avoid linker arguments
#pragma comment(lib, "wsock32.lib") // avoid linker arguments
#endif

using namespace platform;

#if TARGET_OS_IPHONE
#include "common/MemoryStreams.hpp"
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>

void Timer::static_once(CFRunLoopTimerRef impl, void *info) {
	Timer *t = (Timer *) info;
	t->a_handler();
}

void Timer::cancel() {
	if (!impl)
		return;
//    CFRunLoopRemoveTimer(CFRunLoopGetCurrent(), impl, kCFRunLoopDefaultMode);
	CFRunLoopTimerInvalidate(impl);
	CFRelease(impl);
	impl = nullptr;
}

void Timer::once(float after_seconds) {
	cancel();
	CFRunLoopTimerContext TimerContext = {0, this, nullptr, nullptr, nullptr};
	CFAbsoluteTime FireTime = CFAbsoluteTimeGetCurrent() + after_seconds;
	impl = CFRunLoopTimerCreate(kCFAllocatorDefault,
								FireTime,
								0, 0, 0,
								&Timer::static_once,
								&TimerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), impl, kCFRunLoopDefaultMode);
}

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler) :
		rw_handler(rw_handler), d_handler(d_handler),
		readStream(nullptr), writeStream(nullptr) {}

TCPSocket::~TCPSocket() {
	close();
}

void TCPSocket::close() {
	if (readStream) {
		CFReadStreamClose(readStream);
		CFRelease(readStream);
		readStream = nullptr;
	}
	if (writeStream) {
		CFWriteStreamClose(writeStream);
		CFRelease(writeStream);
		writeStream = nullptr;
	}
}

void TCPSocket::close_and_call() {
	bool call = is_open();
	close();
	if (call)
		d_handler();
}

bool TCPSocket::is_open() const {
	return readStream || writeStream;
}

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();
	CFStringRef hname = CFStringCreateWithCString(kCFAllocatorDefault, addr.c_str(), kCFStringEncodingUTF8);
	CFHostRef host = CFHostCreateWithName(kCFAllocatorDefault, hname);
	CFRelease(hname);
	hname = nullptr;
	CFStreamCreatePairWithSocketToCFHost(kCFAllocatorDefault, host, port,
										 &readStream, &writeStream);
	CFRelease(host);
	host = nullptr;
	CFStreamClientContext myContext = {0, this, nullptr, nullptr, nullptr};
	if (!CFReadStreamSetClient(readStream, kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered, &TCPSocket::read_callback, &myContext)) {
		close();
		return false;
	}
	if (!CFWriteStreamSetClient(writeStream, kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered, &TCPSocket::write_callback, &myContext)) {
		close();
		return false;
	}
	CFReadStreamScheduleWithRunLoop(readStream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFWriteStreamScheduleWithRunLoop(writeStream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFReadStreamOpen(readStream); // TODO check err
	CFWriteStreamOpen(writeStream); // TODO check err
	return true;
}

size_t TCPSocket::read_some(void *val, size_t count) {
	if (!readStream || !CFReadStreamHasBytesAvailable(readStream))
		return 0;
	CFIndex bytesRead = CFReadStreamRead(readStream, (unsigned char *) val, count);
	if (bytesRead <= 0) { // error or end of stream
		return 0;
	}
	return bytesRead;
}

size_t TCPSocket::write_some(const void *val, size_t count) {
	if (!writeStream || !CFWriteStreamCanAcceptBytes(writeStream))
		return 0;
	CFIndex bytesWritten = CFWriteStreamWrite(writeStream, (const unsigned char *) val, count);
	if (bytesWritten <= 0) { // error or end of stream
		return 0;
	}
	return bytesWritten;
}

void TCPSocket::shutdown_both() {
	if (!is_open())
		return;
	CFDataRef da = (CFDataRef) CFWriteStreamCopyProperty(writeStream, kCFStreamPropertySocketNativeHandle);
	if (!da)
		return;
	CFSocketNativeHandle handle;
	CFDataGetBytes(da, CFRangeMake(0, sizeof(CFSocketNativeHandle)), (unsigned char *) &handle);
	CFRelease(da);
	::shutdown(handle, SHUT_RDWR);
}

void TCPSocket::read_callback(CFReadStreamRef stream, CFStreamEventType event, void *myPtr) {
	TCPSocket *s = (TCPSocket *) myPtr;
	switch (event) {
		case kCFStreamEventHasBytesAvailable:
			s->rw_handler(true, true);
			break;
		case kCFStreamEventErrorOccurred:
			s->close_and_call();
			//CFStreamError error = CFReadStreamGetError(stream);
			//reportError(error);
			break;
		case kCFStreamEventEndEncountered:
			s->close_and_call();
			break;
	}
}

void TCPSocket::write_callback(CFWriteStreamRef stream, CFStreamEventType event, void *myPtr) {
	TCPSocket *s = (TCPSocket *) myPtr;
	switch (event) {
		case kCFStreamEventCanAcceptBytes:
			s->rw_handler(true, true);
			break;
		case kCFStreamEventErrorOccurred:
			s->close_and_call();
			//CFStreamError error = CFReadStreamGetError(stream);
			//reportError(error);
			break;
		case kCFStreamEventEndEncountered:
			s->close_and_call();
			break;
	}
}

#else // #if TARGET_OS_IPHONE

#include <algorithm>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/array.hpp>

thread_local EventLoop *EventLoop::current_loop = 0;

EventLoop::EventLoop(boost::asio::io_service &io_service) : io_service(io_service) {
	if (current_loop != 0)
		throw std::logic_error("RunLoop::RunLoop Only single RunLoop per thread is allowed");
	current_loop = this;
}

EventLoop::~EventLoop() {
	current_loop = 0;
}

void EventLoop::cancel() {
	io_service.stop();
}

void EventLoop::run() {
	io_service.run();
}
void EventLoop::wake() {
	io_service.post( [](void){} );
}

class Timer::Impl {
public:
	explicit Impl(Timer *owner) : owner(owner), pending_wait(false),
			timer(EventLoop::current()->io()) {}
	Timer *owner;
	bool pending_wait;
	boost::asio::deadline_timer timer;

	void close() {
		Timer *was_owner = owner;
		if (pending_wait) {
			owner = nullptr;
			was_owner->impl.reset();
		}
	}
	void handle_timeout(const boost::system::error_code &e) {
		pending_wait = false;
		if (!e) {
			if (owner)
				owner->a_handler();
			return;
		}
		if (e != boost::asio::error::operation_aborted) {
		}
	}
	void start_timer(float after_seconds) {
		assert(pending_wait == false);
		pending_wait = true;
		timer.expires_from_now(boost::posix_time::milliseconds(static_cast<int>(after_seconds * 1000))); // int because we do not know exact type
		timer.async_wait(boost::bind(&Impl::handle_timeout, owner->impl, boost::asio::placeholders::error));
	}
};

void Timer::cancel() {
	if (impl)
		impl->close();
}

void Timer::once(float after_seconds) {
	cancel();
	if (!impl)
		impl = std::make_shared<Impl>(this);
	impl->start_timer(after_seconds);
}

class TCPSocket::Impl {
public:
	explicit Impl(TCPSocket *owner)
			: owner(owner), connected(false), asked_shutdown(false), pending_read(false), pending_write(false),
			pending_connect(false),
			socket(EventLoop::current()->io()), incoming_buffer(8192), outgoing_buffer(8192) {}
	TCPSocket *owner;
	bool connected;
	bool asked_shutdown;
	bool pending_read;
	bool pending_write;
	bool pending_connect;
	boost::asio::ip::tcp::socket socket;
	common::CircularBuffer incoming_buffer;
	common::CircularBuffer outgoing_buffer;

	void close(bool called_from_run_loop) {
		socket.close();
		TCPSocket *was_owner = owner;
		if (pending_write || pending_read || pending_connect) {
			owner = nullptr;
			if (was_owner) // error can happen on detached impl
				was_owner->impl = std::make_shared<Impl>(was_owner);
		} else {
			connected = false;
			asked_shutdown = false;
			pending_connect = false;
			pending_read = false;
			pending_write = false;
			incoming_buffer.clear();
			outgoing_buffer.clear();
		}
		if (was_owner && called_from_run_loop)
			was_owner->d_handler();
	}
	void start_shutdown() {
		boost::system::error_code ignored_ec;
		socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
	}

	void handle_connect(const boost::system::error_code &e) {
		pending_connect = false;
		if (!e) {
			connected = true;
			start_read();
			start_write();
			if (owner)
				owner->rw_handler(true, true);
			return;
		}
		if (e != boost::asio::error::operation_aborted) {
			close(true);
		}
	}
	void start_read() {
		if (incoming_buffer.full() || pending_read || !connected || !owner)
			return;
		pending_read = true;
		boost::array<boost::asio::mutable_buffer, 2> bufs{{boost::asio::buffer(incoming_buffer.write_ptr(), incoming_buffer.write_count()), boost::asio::buffer(incoming_buffer.write_ptr2(), incoming_buffer.write_count2())}};
		socket.async_read_some(bufs, boost::bind(&Impl::handle_read, owner->impl, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void handle_read(const boost::system::error_code &e, std::size_t bytes_transferred) {
		pending_read = false;
		if (!e) {
			if(!asked_shutdown)
				incoming_buffer.did_write(bytes_transferred);
			start_read();
			if (owner)
				owner->rw_handler(true, true);
			return;
		}
		if (e != boost::asio::error::operation_aborted) {
			close(true);
		}
	}

	void start_write() {
		if (pending_write || !connected || !owner)
			return;
		if (outgoing_buffer.empty()) {
			if (asked_shutdown)
				start_shutdown();
			return;
		}
		pending_write = true;
		boost::array<boost::asio::const_buffer, 2> bufs{{boost::asio::buffer(outgoing_buffer.read_ptr(), outgoing_buffer.read_count()), boost::asio::buffer(outgoing_buffer.read_ptr2(), outgoing_buffer.read_count2())}};
		socket.async_write_some(bufs, boost::bind(&Impl::handle_write, owner->impl, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void handle_write(const boost::system::error_code &e, std::size_t bytes_transferred) {
		pending_write = false;
		if (!e) {
			outgoing_buffer.did_read(bytes_transferred);
			start_write();
			if (owner)
				owner->rw_handler(true, true);
			return;
		}
		if (e != boost::asio::error::operation_aborted) {
			close(true);
		}
	}
};

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler) :
		impl(std::make_shared<Impl>(this)), rw_handler(rw_handler), d_handler(d_handler) {}

TCPSocket::~TCPSocket() {
	close();
}

void TCPSocket::close() {
	impl->close(false);
}

bool TCPSocket::is_open() const {
	return impl->socket.is_open();
}

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();

	try {
		impl->pending_connect = true;
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(addr), port);
		impl->socket.async_connect(endpoint, boost::bind(&TCPSocket::Impl::handle_connect, impl, boost::asio::placeholders::error));
	} catch (const std::exception &) {
		return false;
	}
	return true;
}

size_t TCPSocket::read_some(void *data, size_t size) {
	size_t rc = impl->incoming_buffer.read_some(data, size);
	impl->start_read();
	return rc;
}

size_t TCPSocket::write_some(const void *data, size_t size) {
	if (impl->asked_shutdown)
		return 0;
	size_t wc = impl->outgoing_buffer.write_some(data, size);
	impl->start_write();
	return wc;
}

void TCPSocket::shutdown_both() {
	if (impl->asked_shutdown)
		return;
	impl->asked_shutdown = true;
	impl->incoming_buffer.clear();
	if (impl->connected && !impl->pending_write)
		impl->start_shutdown();
}

class TCPAcceptor::Impl {
public:
	explicit Impl(TCPAcceptor *owner) : owner(owner), pending_accept(false),
			acceptor(EventLoop::current()->io()), socket_being_accepted(EventLoop::current()->io()),
			socket_ready(false) {}
	TCPAcceptor *owner;
	bool pending_accept;
	boost::asio::ip::tcp::acceptor acceptor;
	boost::asio::ip::tcp::socket socket_being_accepted;
	bool socket_ready;

	void close() {
		acceptor.close();
		TCPAcceptor *was_owner = owner;
		owner = nullptr;
		if (pending_accept) {
			if (was_owner) // error can happen on detached impl
				was_owner->impl.reset(); // We do not reuse LA Sockets
		}
	}
	void start_accept() {
		if (!owner)
			return;
		pending_accept = true;
		acceptor.async_accept(socket_being_accepted,
							  boost::bind(&Impl::handle_accept, owner->impl,
										  boost::asio::placeholders::error));
	}
	void handle_accept(const boost::system::error_code &e) {
		pending_accept = false;
		if (!e) {
			socket_ready = true;
			if (owner)
				owner->a_handler();
		}
		if (e != boost::asio::error::operation_aborted) {
			// some nasty problem with socket, say so to the client
		}
	}
};

TCPAcceptor::TCPAcceptor(const std::string &addr, uint16_t port, A_handler a_handler)
		: impl(std::make_shared<Impl>(this)), a_handler(a_handler) {
	boost::asio::ip::tcp::resolver resolver(EventLoop::current()->io());
	boost::asio::ip::tcp::resolver::query query(addr, std::to_string(port));
	boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
	impl->acceptor.open(endpoint.protocol());
	impl->acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	impl->acceptor.bind(endpoint);
	impl->acceptor.listen();

	impl->start_accept();
}

TCPAcceptor::~TCPAcceptor() {
	impl->close();
}

bool TCPAcceptor::accept(TCPSocket &socket, std::string &accepted_addr) {
	if (!impl->socket_ready)
		return false;
	impl->socket_ready = false;
	socket.close();
	std::swap(socket.impl->socket, impl->socket_being_accepted);

	socket.impl->connected = true;
	boost::system::error_code ec;
	auto endpoint = socket.impl->socket.remote_endpoint(ec);
	if( ec )
		return false;
	accepted_addr = endpoint.address().to_string();
	socket.impl->start_read();
	impl->start_accept();
	return true;
}

#endif // #if TARGET_OS_IPHONE
