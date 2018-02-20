// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSING.md for details.

#include "PreventSleep.hpp"
#include <iostream>
#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

using namespace platform;

#if TARGET_OS_IPHONE
// No power modes on iOS, app will run when in foreground
PreventSleep::PreventSleep(const char *reason) {}
PreventSleep::~PreventSleep() {}
#elif TARGET_OS_MAC
#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <atomic>

static std::atomic<int> counter{0};
static IOPMAssertionID assertionID = 0;

PreventSleep::PreventSleep(const char *reason) {
	if (++counter == 1) {
		CFStringRef reasonForActivity = CFStringCreateWithCString(kCFAllocatorDefault, reason, kCFStringEncodingUTF8);
		IOReturn success              = IOPMAssertionCreateWithName(
		    kIOPMAssertionTypeNoDisplaySleep, kIOPMAssertionLevelOn, reasonForActivity, &assertionID);
		CFRelease(reasonForActivity);
		std::cout << "Preventing sleep " << reason << " success=" << success << std::endl;
	}
}
PreventSleep::~PreventSleep() {
	if (--counter == 0) {
		IOReturn success = IOPMAssertionRelease(assertionID);
		std::cout << "Allowing sleep success=" << success << std::endl;
		assertionID = 0;
	}
}

#elif defined(_WIN32)
#include "platform/Windows.hpp"

static thread_local int counter = 0;
PreventSleep::PreventSleep(const char *reason) {
	if (++counter == 1) {
		SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);  // ES_AWAYMODE_REQUIRED - only for media centers
		std::cout << "Preventing sleep " << reason << std::endl;
	}
}
PreventSleep::~PreventSleep() {
	if (--counter == 0) {
		SetThreadExecutionState(ES_CONTINUOUS);
		std::cout << "Allowing sleep" << std::endl;
	}
}

#elif defined(__linux__)
// Sorry, no power modes in '70s
PreventSleep::PreventSleep(const char *reason) {}
PreventSleep::~PreventSleep() {}

#endif
