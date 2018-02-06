#pragma once

namespace platform {

class PreventSleep {
public:
	explicit PreventSleep(const char * reason); // some OSes will show this string to user
	~PreventSleep();
};

}
