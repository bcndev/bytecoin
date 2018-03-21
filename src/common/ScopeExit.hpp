// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <functional>
#include "Nocopy.hpp"

namespace common {

class ScopeExit : private Nocopy {
public:
	explicit ScopeExit(std::function<void()> &&handler) : m_handler(std::move(handler)) {}
	~ScopeExit() {
		if (!m_cancelled)
			m_handler();
	}

	void cancel() { m_cancelled = true; }
	void resume() { m_cancelled = false; }

private:
	std::function<void()> m_handler;
	bool m_cancelled = false;
};
}
