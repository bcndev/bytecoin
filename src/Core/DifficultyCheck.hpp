#pragma once

#include "CryptoNote.hpp"

namespace bytecoin {
struct DifficultyCheck {
	Height height;
	const char *hash;
	Difficulty cumulative_difficulty;
};

extern const DifficultyCheck *difficulty_check;
extern const size_t difficulty_check_count;
}
