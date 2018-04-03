// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "PreventSleep.hpp"
#include <iostream>
#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#if defined(__ANDROID__)
#include <QAndroidJniObject>

static QAndroidJniObject m_wake_lock;
static std::atomic<int> counter{0};

platform::PreventSleep::PreventSleep(const char *reason) {
	if (++counter == 1) {
		QAndroidJniObject activity = QAndroidJniObject::callStaticObjectMethod(
		    "org/qtproject/qt5/android/QtNative", "activity", "()Landroid/app/Activity;");
		if (activity.isValid()) {
			QAndroidJniObject serviceName =
			    QAndroidJniObject::getStaticObjectField<jstring>("android/content/Context", "POWER_SERVICE");
			if (serviceName.isValid()) {
				QAndroidJniObject powerMgr = activity.callObjectMethod(
				    "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", serviceName.object<jobject>());
				if (powerMgr.isValid()) {
					jint levelAndFlags =
					    QAndroidJniObject::getStaticField<jint>("android/os/PowerManager", "SCREEN_DIM_WAKE_LOCK");

					QAndroidJniObject tag = QAndroidJniObject::fromString("My Tag");

					m_wake_lock = powerMgr.callObjectMethod("newWakeLock",
					    "(ILjava/lang/String;)Landroid/os/PowerManager$WakeLock;", levelAndFlags,
					    tag.object<jstring>());
				}
			}
		}
		if (m_wake_lock.isValid()) {
			m_wake_lock.callMethod<void>("acquire", "()V");
			//            qDebug() << "Locked device, can't go to standby anymore";
		}
	}
}
platform::PreventSleep::~PreventSleep() {
	if (--counter == 0) {
		if (m_wake_lock.isValid()) {
			m_wake_lock.callMethod<void>("release", "()V");
			//            qDebug() << "Unlocked device, can now go to standby";
		}
	}
}

#elif TARGET_OS_IPHONE
// No power modes on iOS, app will run when in foreground
platform::PreventSleep::PreventSleep(const char *reason) {}
platform::PreventSleep::~PreventSleep() {}
#elif TARGET_OS_MAC
#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <atomic>

static std::atomic<int> counter{0};
static IOPMAssertionID assertionID = 0;

platform::PreventSleep::PreventSleep(const char *reason) {
	if (++counter == 1) {
		CFStringRef reason_for_activity = CFStringCreateWithCString(kCFAllocatorDefault, reason, kCFStringEncodingUTF8);
		IOReturn success                = IOPMAssertionCreateWithName(
		    kIOPMAssertionTypeNoDisplaySleep, kIOPMAssertionLevelOn, reason_for_activity, &assertionID);
		CFRelease(reason_for_activity);
		std::cout << "Preventing sleep " << reason << " success=" << success << std::endl;
	}
}
platform::PreventSleep::~PreventSleep() {
	if (--counter == 0) {
		IOReturn success = IOPMAssertionRelease(assertionID);
		std::cout << "Allowing sleep success=" << success << std::endl;
		assertionID = 0;
	}
}

#elif defined(_WIN32)
#include "platform/Windows.hpp"

static thread_local int counter = 0;
platform::PreventSleep::PreventSleep(const char *reason) {
	if (++counter == 1) {
		SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);  // ES_AWAYMODE_REQUIRED - only for media centers
		std::cout << "Preventing sleep " << reason << std::endl;
	}
}
platform::PreventSleep::~PreventSleep() {
	if (--counter == 0) {
		SetThreadExecutionState(ES_CONTINUOUS);
		std::cout << "Allowing sleep" << std::endl;
	}
}

#elif defined(__linux__)
// Sorry, no power modes in '70s
platform::PreventSleep::PreventSleep(const char *reason) {}
platform::PreventSleep::~PreventSleep() {}

#endif
