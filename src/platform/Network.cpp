// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Network.hpp"
#include "Time.hpp"
#include "common/MemoryStreams.hpp"
#include "common/string.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")   // Windows SDK sockets
#pragma comment(lib, "wsock32.lib")  // Windows SDK sockets
#endif

using namespace platform;

static std::pair<bool, std::string> split_ssl_address(const std::string &addr) {
	std::string stripped_addr = addr;
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
	return std::make_pair(ssl, stripped_addr);
}
#if defined(__ANDROID__)
#include <QSslSocket>

Timer::Timer(after_handler a_handler) : a_handler(a_handler), impl(nullptr) {
	QObject::connect(&impl, &QTimer::timeout, [this]() { this->a_handler(); });
	impl.setSingleShot(true);
}

void Timer::cancel() { impl.stop(); }

void Timer::once(float after_seconds) {
	cancel();
	impl.start(static_cast<int>(after_seconds * 1000.0f / get_time_multiplier_for_tests()));
}

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler) : rw_handler(rw_handler), d_handler(d_handler) {}

void TCPSocket::close() {
	if (impl) {
		impl->deleteLater();
		impl.release();
	}
	ready = false;
}

bool TCPSocket::is_open() const { return impl && impl->state() != QAbstractSocket::UnconnectedState; }

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();
	//    bool sup = QSslSocket::supportsSsl();
	//    auto vs = QSslSocket::sslLibraryVersionString(); // "BoringSSL"
	//    auto vsv = QSslSocket::sslLibraryBuildVersionString(); // "OpenSSL 1.0.1j 15 Oct 2014"

	auto ssl_addr = split_ssl_address(addr);

	if (ssl_addr.first) {
		auto s = std::make_unique<QSslSocket>();
		QObject::connect(s.get(), static_cast<void (QSslSocket::*)(const QList<QSslError> &)>(&QSslSocket::sslErrors),
		    [this](const QList<QSslError> &errors) {
			    QString str;
			    for (const auto &error : errors)
				    str = error.errorString();
			});
		QObject::connect(s.get(), &QSslSocket::encrypted, [this]() {
			this->ready = true;
			this->rw_handler(true, true);
		});
		QObject::connect(
		    s.get(), &QSslSocket::encryptedBytesWritten, [this](qint64 bytes) { this->rw_handler(true, true); });
		QObject::connect(s.get(), &QAbstractSocket::readyRead, [this]() { this->rw_handler(true, true); });
		QObject::connect(s.get(), &QAbstractSocket::disconnected, [this]() {
			this->close();
			this->d_handler();
		});
		QObject::connect(s.get(),
		    static_cast<void (QAbstractSocket::*)(QAbstractSocket::SocketError)>(&QAbstractSocket::error),
		    [this](QAbstractSocket::SocketError err) {
			    qDebug() << this->impl->errorString();
			    this->close();
			    this->d_handler();
			});
		s->connectToHostEncrypted(QString::fromUtf8(ssl_addr.second.data(), ssl_addr.second.size()), port);
		impl = std::move(s);
	} else {
		impl = std::make_unique<QTcpSocket>();
		QObject::connect(
		    impl.get(), &QAbstractSocket::bytesWritten, [this](qint64 bytes) { this->rw_handler(true, true); });
		QObject::connect(impl.get(), &QAbstractSocket::connected, [this]() {
			this->ready = true;
			this->rw_handler(true, true);
		});
		QObject::connect(impl.get(), &QAbstractSocket::readyRead, [this]() { this->rw_handler(true, true); });
		QObject::connect(impl.get(), &QAbstractSocket::disconnected, [this]() {
			this->close();
			this->d_handler();
		});
		QObject::connect(impl.get(),
		    static_cast<void (QAbstractSocket::*)(QAbstractSocket::SocketError)>(&QAbstractSocket::error),
		    [this](QAbstractSocket::SocketError err) {
			    this->close();
			    this->d_handler();
			});
		impl->connectToHost(QString::fromUtf8(ssl_addr.second.data(), ssl_addr.second.size()), port);
	}
	return true;
}

size_t TCPSocket::read_some(void *val, size_t count) {
	qint64 res = (impl && ready) ? impl->read(reinterpret_cast<char *>(val), count) : 0;
	if (res != 0)
		res += 0;
	return res;
}

size_t TCPSocket::write_some(const void *val, size_t count) {
	qint64 res = (impl && ready) ? impl->write(reinterpret_cast<const char *>(val), count) : 0;
	return res;
}

void TCPSocket::shutdown_both() {
	if (impl)
		impl->disconnectFromHost();
}

#elif TARGET_OS_IPHONE
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
	CFAbsoluteTime FireTime            = CFAbsoluteTimeGetCurrent() + after_seconds / get_time_multiplier_for_tests();
	impl = CFRunLoopTimerCreate(kCFAllocatorDefault, FireTime, 0, 0, 0, &Timer::static_once, &TimerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), impl, kCFRunLoopDefaultMode);
}

void TCPSocket::close() {
	if (read_stream) {
		CFReadStreamClose(read_stream);
		CFRelease(read_stream);
		read_stream = nullptr;
	}
	if (write_stream) {
		CFWriteStreamClose(write_stream);
		CFRelease(write_stream);
		write_stream = nullptr;
	}
}

void TCPSocket::close_and_call() {
	bool call = is_open();
	close();
	if (call)
		d_handler();
}

bool TCPSocket::is_open() const { return read_stream || write_stream; }

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();
	auto ssl_addr     = split_ssl_address(addr);
	CFStringRef hname = CFStringCreateWithCString(kCFAllocatorDefault, ssl_addr.second.c_str(), kCFStringEncodingUTF8);
	CFHostRef host    = CFHostCreateWithName(kCFAllocatorDefault, hname);
	CFRelease(hname);
	hname = nullptr;
	CFStreamCreatePairWithSocketToCFHost(kCFAllocatorDefault, host, port, &read_stream, &write_stream);
	CFRelease(host);
	host = nullptr;
	//	CFReadStreamSetProperty(read_stream, NSStreamSocketSecurityLevelKey, securityDictRef);
	if (ssl_addr.first) {
		CFMutableDictionaryRef security_dict_ref = CFDictionaryCreateMutable(
		    kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		if (!security_dict_ref) {
			close();
			return false;
		}
		CFDictionarySetValue(security_dict_ref, kCFStreamSSLValidatesCertificateChain, kCFBooleanTrue);
		CFReadStreamSetProperty(read_stream, kCFStreamPropertySSLSettings, security_dict_ref);
		CFRelease(security_dict_ref);
		security_dict_ref = nullptr;
	}
	CFStreamClientContext my_context = {0, this, nullptr, nullptr, nullptr};
	if (!CFReadStreamSetClient(read_stream,
	        kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
	        &TCPSocket::read_callback, &my_context)) {
		close();
		return false;
	}
	if (!CFWriteStreamSetClient(write_stream,
	        kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered,
	        &TCPSocket::write_callback, &my_context)) {
		close();
		return false;
	}
	CFReadStreamScheduleWithRunLoop(read_stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFWriteStreamScheduleWithRunLoop(write_stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	CFReadStreamOpen(read_stream);
	CFWriteStreamOpen(write_stream);
	return true;
}

size_t TCPSocket::read_some(void *val, size_t count) {
	if (!read_stream || !CFReadStreamHasBytesAvailable(read_stream))
		return 0;
	CFIndex bytes_read = CFReadStreamRead(read_stream, (unsigned char *)val, count);
	if (bytes_read <= 0) {  // error or end of stream
		return 0;
	}
	return bytes_read;
}

size_t TCPSocket::write_some(const void *val, size_t count) {
	if (!write_stream || !CFWriteStreamCanAcceptBytes(write_stream))
		return 0;
	CFIndex bytes_written = CFWriteStreamWrite(write_stream, (const unsigned char *)val, count);
	if (bytes_written <= 0) {  // error or end of stream
		return 0;
	}
	return bytes_written;
}

void TCPSocket::shutdown_both() {
	if (!is_open())
		return;
	CFDataRef da = (CFDataRef)CFWriteStreamCopyProperty(write_stream, kCFStreamPropertySocketNativeHandle);
	if (!da)
		return;
	CFSocketNativeHandle handle;
	CFDataGetBytes(da, CFRangeMake(0, sizeof(CFSocketNativeHandle)), (unsigned char *)&handle);
	CFRelease(da);
	::shutdown(handle, SHUT_RDWR);
}

void TCPSocket::read_callback(CFReadStreamRef stream, CFStreamEventType event, void *my_ptr) {
	TCPSocket *s = (TCPSocket *)my_ptr;
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

void TCPSocket::write_callback(CFWriteStreamRef stream, CFStreamEventType event, void *my_ptr) {
	TCPSocket *s = (TCPSocket *)my_ptr;
	switch (event) {
	case kCFStreamEventCanAcceptBytes:
		s->rw_handler(true, true);
		break;
	case kCFStreamEventErrorOccurred:
		s->close_and_call();
		// CFStreamError error = CFReadStreamGetError(stream);
		// report_error(error);
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

using namespace std::placeholders;  // We enjoy standard bindings

#if platform_USE_SSL
#include <boost/asio/ssl.hpp>

namespace ssl = boost::asio::ssl;
typedef ssl::stream<boost::asio::ip::tcp::socket> SSLSocket;

// We need a timer fix from 1.62 to prevent (very rare) segfaults in asio::detail::timer_queue::remove_timer
static_assert(BOOST_VERSION / 100000 == 1 && ((BOOST_VERSION / 100) % 1000) >= 62,
    "You need at least boost 1.62, you are compiling with " BOOST_LIB_VERSION);

#ifdef _WIN32
#include <Wincrypt.h>
#pragma comment(lib, "libcrypto.lib")  // OpenSSL library
#pragma comment(lib, "libssl.lib")     // OpenSSL library
#pragma comment(lib, "crypt32.lib")    // Windows SDK dependency of OpenSSL

static void add_system_root_certs(ssl::context &ctx) {
	HCERTSTORE h_store = CertOpenSystemStore(0, "ROOT");
	if (h_store == NULL)
		return;
	X509_STORE *store        = X509_STORE_new();
	PCCERT_CONTEXT p_context = NULL;
	while ((p_context = CertEnumCertificatesInStore(h_store, p_context)) != NULL) {
		// convert from DER to internal format
		X509 *x509 = d2i_X509(NULL, (const unsigned char **)&p_context->pbCertEncoded, p_context->cbCertEncoded);
		if (x509 != NULL) {
			X509_STORE_add_cert(store, x509);
			X509_free(x509);
		}
	}

	CertFreeCertificateContext(p_context);
	CertCloseStore(h_store, 0);

	SSL_CTX_set_cert_store(ctx.native_handle(), store);
}
#else
// https://letsencrypt.org/certs/isrgrootx1.pem.txt
static const char our_cert[] = R"(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)";
// https://www.identrust.com/certificates/trustid/root-download-x3.html (converted to pem)
static const char our_cert2[] = R"(
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
)";
static void add_system_root_certs(ssl::context &ctx) {
	// We try all methods and hope for the best
	ctx.set_default_verify_paths();
	ctx.add_verify_path("/etc/ssl/certs");  // read below for the cert folder mess on Linux
	// https://www.happyassassin.net/2015/01/12/a-note-about-ssltls-trusted-certificate-stores-and-platforms/
	boost::asio::const_buffer cert(our_cert, sizeof(our_cert) - 1);
	ctx.add_certificate_authority(cert);
	boost::asio::const_buffer cert2(our_cert2, sizeof(our_cert2) - 1);
	ctx.add_certificate_authority(cert2);
}
#endif

// static thread_local std::shared_ptr<ssl::context> shared_client_context;
#endif

thread_local EventLoop *EventLoop::current_loop = nullptr;

EventLoop::EventLoop(boost::asio::io_service &io_service) : io_service(io_service) {
	if (current_loop != 0)
		throw std::logic_error("RunLoop::RunLoop Only single RunLoop per thread is allowed");
	current_loop = this;
}

EventLoop::~EventLoop() {
	current_loop = nullptr;
	//#if platform_USE_SSL
	//	shared_client_context.reset();
	//#endif
}

void EventLoop::cancel() { io_service.stop(); }

void EventLoop::run() { io_service.run(); }
void EventLoop::wake() {
	io_service.post([](void) {});
}

// static bool ispowerof2(unsigned int x) {
//    return x && !(x & (x - 1));
//}
// static unsigned global_timer_impl_counter = 0;

class Timer::Impl {
public:
	explicit Impl(Timer *owner) : owner(owner), pending_wait(false), timer(EventLoop::current()->io()) {
		//		global_timer_impl_counter += 1;
		//		if( ispowerof2(global_timer_impl_counter) )
		//		    std::cout << "++Timer::Impl::counter=" << global_timer_impl_counter << std::endl;
	}
	~Impl() {
		//      if( ispowerof2(global_timer_impl_counter) )
		//            std::cout << "--Timer::Impl::counter=" << global_timer_impl_counter << std::endl;
		//		global_timer_impl_counter -= 1;
	}
	Timer *owner;
	bool pending_wait;
	boost::asio::deadline_timer timer;

	void close() {
		Timer *was_owner = owner;
		if (pending_wait) {
			owner = nullptr;
			was_owner->impl.reset();
			boost::system::error_code ec;
			timer.cancel(ec);  // Prevent exceptions
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
		timer.async_wait(std::bind(&Impl::handle_timeout, owner->impl, _1));
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
	impl->start_timer(after_seconds / get_time_multiplier_for_tests());
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
#if platform_USE_SSL
	std::shared_ptr<ssl::context> ssl_context;  // TCP socket may live longer than TCP acceptor
	std::unique_ptr<SSLSocket> ssl_socket;
#endif
	common::CircularBuffer incoming_buffer;
	common::CircularBuffer outgoing_buffer;

	void close(bool called_from_run_loop) {
#if platform_USE_SSL
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
#if platform_USE_SSL
			ssl_socket.reset();
			ssl_context.reset();
#endif
		}
		if (was_owner && called_from_run_loop)
			was_owner->d_handler();
	}
	void start_shutdown() {
		boost::system::error_code ignored_ec;
#if platform_USE_SSL
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
#if platform_USE_SSL
			if (ssl_socket) {
				start_handshake(ssl::stream_base::client);
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
#if platform_USE_SSL
		if (ssl_socket)
			ssl_socket->async_read_some(bufs, std::bind(&Impl::handle_read, owner->impl, _1, _2));
		else
#endif
			socket.async_read_some(bufs, std::bind(&Impl::handle_read, owner->impl, _1, _2));
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
			//			std::cout << e << " " << e.message() << std::endl;
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
#if platform_USE_SSL
		if (ssl_socket)
			ssl_socket->async_write_some(bufs, std::bind(&Impl::handle_write, owner->impl, _1, _2));
		else
#endif
			socket.async_write_some(bufs, std::bind(&Impl::handle_write, owner->impl, _1, _2));
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
#if platform_USE_SSL
	void start_handshake(ssl::stream_base::handshake_type type) {
		ssl_socket->async_handshake(type, std::bind(&Impl::handle_handshake, this, _1));
	}
	void handle_handshake(const boost::system::error_code &e) {
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
			std::cout << e << " " << e.message() << std::endl;
			close(true);
		}
	}
#endif
};

TCPSocket::TCPSocket(RW_handler rw_handler, D_handler d_handler)
    : impl(std::make_shared<Impl>(this)), rw_handler(rw_handler), d_handler(d_handler) {}

TCPSocket::~TCPSocket() { close(); }

void TCPSocket::close() { impl->close(false); }

bool TCPSocket::is_open() const {
#if platform_USE_SSL
	if (impl->ssl_socket)
		return impl->ssl_socket->lowest_layer().is_open();
#endif
	return impl->socket.lowest_layer().is_open();
}

bool TCPSocket::connect(const std::string &addr, uint16_t port) {
	close();

	auto ssl_addr = split_ssl_address(addr);
	try {
		impl->pending_connect = true;
		if (ssl_addr.first) {
#if platform_USE_SSL
			boost::asio::ip::tcp::resolver resolver(EventLoop::current()->io());
			boost::asio::ip::tcp::resolver::query query(ssl_addr.second, common::to_string(port));
			boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);
			for (; iter != boost::asio::ip::tcp::resolver::iterator(); ++iter)
				if (iter->endpoint().address().is_v4())
					break;
			if (iter == boost::asio::ip::tcp::resolver::iterator())
				return false;
			std::shared_ptr<ssl::context> shared_client_context =
			    std::make_shared<ssl::context>(ssl::context::tlsv12_client);
			add_system_root_certs(*shared_client_context);
			shared_client_context->set_verify_mode(ssl::verify_peer);
			shared_client_context->set_verify_callback(ssl::rfc2818_verification(ssl_addr.second));

			impl->ssl_context = shared_client_context;
			impl->ssl_socket  = std::make_unique<SSLSocket>(EventLoop::current()->io(), *impl->ssl_context);
			if (!SSL_set_tlsext_host_name(impl->ssl_socket->native_handle(), ssl_addr.second.c_str()))
				return false;
			impl->ssl_socket->lowest_layer().async_connect(
			    iter->endpoint(), std::bind(&TCPSocket::Impl::handle_connect, impl, _1));
#else
			return false;
#endif
		} else {
			boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(ssl_addr.second), port);
			impl->socket.async_connect(endpoint, std::bind(&TCPSocket::Impl::handle_connect, impl, _1));
		}
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
#if platform_USE_SSL
	    , ssl_context(std::make_shared<ssl::context>(ssl::context::sslv23))
	    , ssl_socket_being_accepted(
	          ssl ? std::make_unique<SSLSocket>(EventLoop::current()->io(), *ssl_context) : nullptr)
#endif
	    , socket_ready(false) {
	}
	TCPAcceptor *owner;
	const bool ssl;
	bool pending_accept;
	boost::asio::ip::tcp::acceptor acceptor;
	boost::asio::ip::tcp::socket socket_being_accepted;
#if platform_USE_SSL
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
#if platform_USE_SSL
		if (ssl)
			acceptor.async_accept(
			    ssl_socket_being_accepted->next_layer(), std::bind(&Impl::handle_accept, owner->impl, _1));
		else
#endif
			acceptor.async_accept(socket_being_accepted, std::bind(&Impl::handle_accept, owner->impl, _1));
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

#if platform_USE_SSL
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
	boost::asio::ip::tcp::resolver::query query(addr, common::to_string(port));
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
#if platform_USE_SSL
	std::swap(socket.impl->ssl_socket, impl->ssl_socket_being_accepted);
	auto endpoint =
	    impl->ssl ? socket.impl->ssl_socket->next_layer().remote_endpoint(ec) : socket.impl->socket.remote_endpoint(ec);
#else
	auto endpoint = socket.impl->socket.remote_endpoint(ec);
#endif

	if (ec) {
		impl->start_accept();
		return false;
	}
	accepted_addr = endpoint.address().to_string();
#if platform_USE_SSL
	if (impl->ssl) {
		if (!impl->ssl_socket_being_accepted)
			impl->ssl_socket_being_accepted =
			    std::make_unique<SSLSocket>(EventLoop::current()->io(), *impl->ssl_context);
		socket.impl->ssl_context = impl->ssl_context;
		socket.impl->start_handshake(ssl::stream_base::server);
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

// Code to stress-test timers
// std::vector<std::unique_ptr<platform::Timer>> timers;
//
// void timers_handler(size_t pos){
//	std::cout << "Fired " << pos << std::endl;
//	size_t rand1 = crypto::rand<uint64_t>() % timers.size();
//	size_t rand2 = crypto::rand<uint64_t>() % timers.size();
//	size_t rand3 = crypto::rand<uint64_t>() % timers.size();
//	size_t rand4 = crypto::rand<uint64_t>() % timers.size();
//	float rand_t = (crypto::rand<uint64_t>() % 5000) / 1000.0f;
//	timers.at(rand1)->cancel();
//	timers.at(rand2)->cancel();
//	timers.at(rand3)->once(rand_t);
//	timers.at(rand3)->once(rand_t);
//	timers.at(rand4)->once(rand_t + 0.5f);
//}
//
// static int test_timers(){
//	boost::asio::io_service io;
//	platform::EventLoop run_loop(io);
//
//	for(size_t i = 0; i != 50000; ++i)
//		timers.push_back( std::make_unique<platform::Timer>(std::bind(&timers_handler, i)) );
//	timers.at(0)->once(1);
//
//	while (!io.stopped()) {
//		io.run_one();
//	}
//	return 0;
//}
