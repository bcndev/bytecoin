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

#include <functional>
#include "Nocopy.hpp"

namespace common {

class ScopeExit : private Nocopy {
public:
	explicit ScopeExit(std::function<void()> &&handler):
		m_handler(std::move(handler)) {}
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
