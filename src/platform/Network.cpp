// Copyright (c) 2012-2018, The CryptoNote developers, The Byterub developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "Network.hpp"
#include "common/MemoryStreams.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")   // Windows SDK sockets
#pragma comment(lib, "wsock32.lib")  // Windows SDK sockets
#endif

using namespace platform;

#if TARGET_OS_IPHONE
#include <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include "common/MemoryStreams.hpp"

void Timer::static_once(CFRunLoopTimerRef impl, void *info) {
	Timer *t = (Timer *)info;
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
	CFAbsoluteTime FireTime            = CFAbsoluteTimeGetCurrent() + after_seconds;
	impl = CFRunLoopTimerCreate(kCFAllocatorDefault, FireTime, 0, 0, 0, &Timer::static_once, &TimerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), impl, kCFRunLoopDefaultMode);
}

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler)
    : rw_handler(rw_handler), d_handler(d_handler), readStream(nullptr), writeStream(nullptr) {}

TCPSocket::~TCPSocket() { close(); }

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

bool TCPSocket::is_open() const { return readStream || writeStream; }

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();
	CFStringRef hname = CFStringCreateWithCString(kCFAllocatorDefault, addr.c_str(), kCFStringEncodingUTF8);
	CFHostRef host    = CFHostCreateWithName(kCFAllocatorDefault, hname);
	CFRelease(hname);
	hname = nullptr;
	CFStreamCreatePairWithSocketToCFHost(kCFAllocatorDefault, host, port, &readStream, &writeStream);
	CFRelease(host);
	host = nullptr;
	//	CFReadStreamSetProperty(readStream, NSStreamSocketSecurityLevelKey, securityDictRef);
	CFMutableDictionaryRef securityDictRef = CFDictionaryCreateMutable(
	    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!securityDictRef) {
		close();
		return false;
	}
	CFDictionarySetValue(securityDictRef, kCFStreamSSLValidatesCertificateChain, kCFBooleanTrue);
	CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, securityDictRef);
	CFRelease(securityDictRef);
	securityDictRef = nullptr;

	CFStreamClientContext myContext = {0, this, nullptr, nullptr, nullptr};
	if (!CFReadStreamSetClient(readStream,
	        kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
	        &TCPSocket::read_callback, &myContext)) {
		close();
		return false;
	}
	if (!CFWriteStreamSetClient(writeStream,
	        kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
	        &TCPSocket::write_callback, &myContext)) {
		close();
		return false;
	}
	CFReadStreamScheduleWithRunLoop(readStream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFWriteStreamScheduleWithRunLoop(writeStream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFReadStreamOpen(readStream);    // TODO check err
	CFWriteStreamOpen(writeStream);  // TODO check err
	return true;
}

size_t TCPSocket::read_some(void *val, size_t count) {
	if (!readStream || !CFReadStreamHasBytesAvailable(readStream))
		return 0;
	CFIndex bytesRead = CFReadStreamRead(readStream, (unsigned char *)val, count);
	if (bytesRead <= 0) {  // error or end of stream
		return 0;
	}
	return bytesRead;
}

size_t TCPSocket::write_some(const void *val, size_t count) {
	if (!writeStream || !CFWriteStreamCanAcceptBytes(writeStream))
		return 0;
	CFIndex bytesWritten = CFWriteStreamWrite(writeStream, (const unsigned char *)val, count);
	if (bytesWritten <= 0) {  // error or end of stream
		return 0;
	}
	return bytesWritten;
}

void TCPSocket::shutdown_both() {
	if (!is_open())
		return;
	CFDataRef da = (CFDataRef)CFWriteStreamCopyProperty(writeStream, kCFStreamPropertySocketNativeHandle);
	if (!da)
		return;
	CFSocketNativeHandle handle;
	CFDataGetBytes(da, CFRangeMake(0, sizeof(CFSocketNativeHandle)), (unsigned char *)&handle);
	CFRelease(da);
	::shutdown(handle, SHUT_RDWR);
}

void TCPSocket::read_callback(CFReadStreamRef stream, CFStreamEventType event, void *myPtr) {
	TCPSocket *s = (TCPSocket *)myPtr;
	switch (event) {
	case kCFStreamEventHasBytesAvailable:
		s->rw_handler(true, true);
		break;
	case kCFStreamEventErrorOccurred: {
		CFStreamError error = CFReadStreamGetError(stream);
		if (error.domain == kCFStreamErrorDomainPOSIX) {
		} else if (error.domain == kCFStreamErrorDomainMacOSStatus) {
		}
		s->close_and_call();
		break;
	}
	case kCFStreamEventEndEncountered:
		s->close_and_call();
		break;
	}
}

void TCPSocket::write_callback(CFWriteStreamRef stream, CFStreamEventType event, void *myPtr) {
	TCPSocket *s = (TCPSocket *)myPtr;
	switch (event) {
	case kCFStreamEventCanAcceptBytes:
		s->rw_handler(true, true);
		break;
	case kCFStreamEventErrorOccurred:
		s->close_and_call();
		// CFStreamError error = CFReadStreamGetError(stream);
		// reportError(error);
		break;
	case kCFStreamEventEndEncountered:
		s->close_and_call();
		break;
	}
}

#else  // #if TARGET_OS_IPHONE

#include <algorithm>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>

#if BYTERUB_SSL
#include <boost/asio/ssl.hpp>
namespace ssl = boost::asio::ssl;
typedef ssl::stream<boost::asio::ip::tcp::socket> SSLSocket;

#ifdef _WIN32
#pragma comment(lib, "libcrypto.lib")  // OpenSSL library
#pragma comment(lib, "libssl.lib")     // OpenSSL library
#pragma comment(lib, "crypt32.lib")    // Windows SDK dependency of OpenSSL

static void add_system_root_certs(ssl::context &ctx) {
	HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
	if (hStore == NULL)
		return;
	X509_STORE *store       = X509_STORE_new();
	PCCERT_CONTEXT pContext = NULL;
	while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
		// convert from DER to internal format
		X509 *x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded);
		if (x509 != NULL) {
			X509_STORE_add_cert(store, x509);
			X509_free(x509);
		}
	}

	CertFreeCertificateContext(pContext);
	CertCloseStore(hStore, 0);

	SSL_CTX_set_cert_store(ctx.native_handle(), store);
}
#else
static void add_system_root_certs(ssl::context &ctx) { ctx.set_default_verify_paths(); }
#endif

static thread_local std::shared_ptr<ssl::context> shared_client_context;
#endif

thread_local EventLoop *EventLoop::current_loop = 0;

EventLoop::EventLoop(boost::asio::io_service &io_service) : io_service(io_service) {
	if (current_loop != 0)
		throw std::logic_error("RunLoop::RunLoop Only single RunLoop per thread is allowed");
	current_loop = this;
}

EventLoop::~EventLoop() {
	current_loop = 0;
#if BYTERUB_SSL
	shared_client_context.reset();
#endif
}

void EventLoop::cancel() { io_service.stop(); }

void EventLoop::run() { io_service.run(); }
void EventLoop::wake() {
	io_service.post([](void) {});
}

class Timer::Impl {
public:
	explicit Impl(Timer *owner) : owner(owner), pending_wait(false), timer(EventLoop::current()->io()) {}
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
		timer.expires_from_now(boost::posix_time::milliseconds(
		    static_cast<int>(after_seconds * 1000)));  // int because we do not know exact type
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
	    : owner(owner)
	    , connected(false)
	    , asked_shutdown(false)
	    , pending_read(false)
	    , pending_write(false)
	    , pending_connect(false)
	    , socket(EventLoop::current()->io())
	    , incoming_buffer(8192)
	    , outgoing_buffer(8192) {}
	TCPSocket *owner;
	bool connected;
	bool asked_shutdown;
	bool pending_read;
	bool pending_write;
	bool pending_connect;
	boost::asio::ip::tcp::socket socket;
#if BYTERUB_SSL
	std::shared_ptr<ssl::context> ssl_context;  // TCP socket may live longer than TCP acceptor
	std::unique_ptr<SSLSocket> ssl_socket;
#endif
	common::CircularBuffer incoming_buffer;
	common::CircularBuffer outgoing_buffer;

	void close(bool called_from_run_loop) {
#if BYTERUB_SSL
		if (ssl_socket)
			ssl_socket->lowest_layer().close();
		else
#endif
			socket.close();
		TCPSocket *was_owner = owner;
		if (pending_write || pending_read || pending_connect) {
			owner = nullptr;
			if (was_owner)  // error can happen on detached impl
				was_owner->impl = std::make_shared<Impl>(was_owner);
		} else {
			connected       = false;
			asked_shutdown  = false;
			pending_connect = false;
			pending_read    = false;
			pending_write   = false;
			incoming_buffer.clear();
			outgoing_buffer.clear();
#if BYTERUB_SSL
			ssl_socket.reset();
			ssl_context.reset();
#endif
		}
		if (was_owner && called_from_run_loop)
			was_owner->d_handler();
	}
	void start_shutdown() {
		boost::system::error_code ignored_ec;
#if BYTERUB_SSL
		if (ssl_socket) {
			// TODO -
			// https://stackoverflow.com/questions/32046034/what-is-the-proper-way-to-securely-disconnect-an-asio-ssl-socket
			ssl_socket->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
		} else
#endif
			socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
	}

	void handle_connect(const boost::system::error_code &e) {
		if (!e) {
#if BYTERUB_SSL
			if (ssl_socket) {
				start_server_handshake();
				return;
			}
#endif
			pending_connect = false;
			connected       = true;
			start_read();
			start_write();
			if (owner)
				owner->rw_handler(true, true);
			return;
		}
		pending_connect = false;
		if (e != boost::asio::error::operation_aborted) {
			close(true);
		}
	}
	void start_read() {
		if (incoming_buffer.full() || pending_read || !connected || !owner)
			return;
		pending_read = true;
		boost::array<boost::asio::mutable_buffer, 2> bufs{
		    {boost::asio::buffer(incoming_buffer.write_ptr(), incoming_buffer.write_count()),
		        boost::asio::buffer(incoming_buffer.write_ptr2(), incoming_buffer.write_count2())}};
#if BYTERUB_SSL
		if (ssl_socket)
			ssl_socket->async_read_some(
			    bufs, boost::bind(&Impl::handle_read, owner->impl, boost::asio::placeholders::error,
			              boost::asio::placeholders::bytes_transferred));
		else
#endif
			socket.async_read_some(bufs, boost::bind(&Impl::handle_read, owner->impl, boost::asio::placeholders::error,
			                                 boost::asio::placeholders::bytes_transferred));
	}

	void handle_read(const boost::system::error_code &e, std::size_t bytes_transferred) {
		pending_read = false;
		if (!e) {
			if (!asked_shutdown)
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
		boost::array<boost::asio::const_buffer, 2> bufs{
		    {boost::asio::buffer(outgoing_buffer.read_ptr(), outgoing_buffer.read_count()),
		        boost::asio::buffer(outgoing_buffer.read_ptr2(), outgoing_buffer.read_count2())}};
#if BYTERUB_SSL
		if (ssl_socket)
			ssl_socket->async_write_some(
			    bufs, boost::bind(&Impl::handle_write, owner->impl, boost::asio::placeholders::error,
			              boost::asio::placeholders::bytes_transferred));
		else
#endif
			socket.async_write_some(
			    bufs, boost::bind(&Impl::handle_write, owner->impl, boost::asio::placeholders::error,
			              boost::asio::placeholders::bytes_transferred));
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
#if BYTERUB_SSL
	void start_server_handshake() {
		ssl_socket->async_handshake(ssl::stream_base::server,
		    boost::bind(&Impl::handle_server_handshake, this, boost::asio::placeholders::error));
	}
	void handle_server_handshake(const boost::system::error_code &e) {
		pending_connect = false;
		if (!e) {
			connected = true;
			start_read();
			start_write();
			return;
		}
		if (e != boost::asio::error::operation_aborted) {
			close(true);
		}
	}
#endif
};

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler)
    : impl(std::make_shared<Impl>(this)), rw_handler(rw_handler), d_handler(d_handler) {}

TCPSocket::~TCPSocket() { close(); }

void TCPSocket::close() { impl->close(false); }

bool TCPSocket::is_open() const { return impl->socket.lowest_layer().is_open(); }

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();

	std::string stripped_addr = addr;
#if BYTERUB_SSL
	bool ssl                  = false;
	const std::string prefix1("https://");
	const std::string prefix2("ssl://");
	if (addr.find(prefix1) == 0) {
		stripped_addr = addr.substr(prefix1.size());
		ssl           = true;
	} else if (addr.find(prefix2) == 0) {
		stripped_addr = addr.substr(prefix2.size());
		ssl           = true;
	}
#endif
	try {
		impl->pending_connect = true;
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(stripped_addr), port);
#if BYTERUB_SSL
		if (ssl) {
			if (shared_client_context == nullptr) {
				shared_client_context = std::make_shared<ssl::context>(ssl::context::tlsv12_client);
				shared_client_context->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
				                                   ssl::context::no_sslv3 | ssl::context::tlsv12_client);
				add_system_root_certs(*shared_client_context);
				shared_client_context->set_verify_mode(ssl::verify_peer);
				shared_client_context->set_verify_callback(ssl::rfc2818_verification(stripped_addr));
			}
			impl->ssl_context = shared_client_context;
			impl->ssl_socket  = std::make_unique<SSLSocket>(EventLoop::current()->io(), *impl->ssl_context);
			impl->ssl_socket->lowest_layer().async_connect(
			    endpoint, boost::bind(&TCPSocket::Impl::handle_connect, impl, boost::asio::placeholders::error));
		} else
#endif
			impl->socket.async_connect(
			    endpoint, boost::bind(&TCPSocket::Impl::handle_connect, impl, boost::asio::placeholders::error));
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
	explicit Impl(TCPAcceptor *owner, bool ssl)
	    : owner(owner)
	    , ssl(ssl)
	    , pending_accept(false)
	    , acceptor(EventLoop::current()->io())
	    , socket_being_accepted(EventLoop::current()->io())
#if BYTERUB_SSL
	    , ssl_context(std::make_shared<ssl::context>(ssl::context::sslv23))
	    , ssl_socket_being_accepted(std::make_unique<SSLSocket>(EventLoop::current()->io(), *ssl_context))
#endif
	    , socket_ready(false) {
	}
	TCPAcceptor *owner;
	const bool ssl;
	bool pending_accept;
	boost::asio::ip::tcp::acceptor acceptor;
	boost::asio::ip::tcp::socket socket_being_accepted;
#if BYTERUB_SSL
	std::shared_ptr<ssl::context> ssl_context;
	std::unique_ptr<SSLSocket> ssl_socket_being_accepted;
#endif
	bool socket_ready;

	void close() {
		acceptor.close();
		TCPAcceptor *was_owner = owner;
		owner                  = nullptr;
		if (pending_accept) {
			if (was_owner)                // error can happen on detached impl
				was_owner->impl.reset();  // We do not reuse LA Sockets
		}
	}
	void start_accept() {
		if (!owner)
			return;
		pending_accept = true;
#if BYTERUB_SSL
		if (ssl)
			acceptor.async_accept(ssl_socket_being_accepted->next_layer(),
			    boost::bind(&Impl::handle_accept, owner->impl, boost::asio::placeholders::error));
		else
#endif
			acceptor.async_accept(socket_being_accepted,
			    boost::bind(&Impl::handle_accept, owner->impl, boost::asio::placeholders::error));
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

TCPAcceptor::TCPAcceptor(const std::string &addr, uint16_t port, A_handler a_handler, const std::string &ssl_pem_file,
    const std::string &ssl_certificate_password)
    : impl(std::make_shared<Impl>(this, !ssl_pem_file.empty())), a_handler(a_handler) {

#if BYTERUB_SSL
	if (impl->ssl) {
		impl->ssl_context->set_options(
		    ssl::context::default_workarounds | ssl::context::no_sslv2);  // | ssl::context::single_dh_use
		impl->ssl_context->set_password_callback(
		    [ssl_certificate_password](std::size_t max_length, ssl::context::password_purpose purpose) -> std::string {
			    return ssl_certificate_password;
			});
		impl->ssl_context->use_certificate_chain_file(ssl_pem_file);
		impl->ssl_context->use_private_key_file(ssl_pem_file, ssl::context::pem);
		//	impl->ssl_context.use_tmp_dh_file("dh512.pem");
	}
#endif
	boost::asio::ip::tcp::resolver resolver(EventLoop::current()->io());
	boost::asio::ip::tcp::resolver::query query(addr, std::to_string(port));
	boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
	impl->acceptor.open(endpoint.protocol());
	impl->acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	impl->acceptor.bind(endpoint);
	impl->acceptor.listen();

	impl->start_accept();
}

TCPAcceptor::~TCPAcceptor() { impl->close(); }

// Usefull link if you wish to generate valid certificates for servers running locally
// https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/

bool TCPAcceptor::accept(TCPSocket &socket, std::string &accepted_addr) {
	if (!impl->socket_ready)
		return false;
	impl->socket_ready = false;
	socket.close();
	std::swap(socket.impl->socket, impl->socket_being_accepted);
	boost::system::error_code ec;
#if BYTERUB_SSL
	std::swap(socket.impl->ssl_socket, impl->ssl_socket_being_accepted);
	auto endpoint =
	    impl->ssl ? socket.impl->ssl_socket->next_layer().remote_endpoint(ec) : socket.impl->socket.remote_endpoint(ec);
#else
	auto endpoint = socket.impl->socket.remote_endpoint(ec);
#endif

	if (ec)
		return false;
	accepted_addr = endpoint.address().to_string();
#if BYTERUB_SSL
	if (impl->ssl) {
		if (!impl->ssl_socket_being_accepted)
			impl->ssl_socket_being_accepted =
			    std::make_unique<SSLSocket>(EventLoop::current()->io(), *impl->ssl_context);
		socket.impl->ssl_context = impl->ssl_context;
		socket.impl->start_server_handshake();
	} else
#endif
	{
		socket.impl->connected = true;
		socket.impl->start_read();
	}
	impl->start_accept();
	return true;
}

#endif  // #if TARGET_OS_IPHONE
