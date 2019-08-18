#pragma once
#include <libnet.h>

namespace spoof {
class HeaderBase {


public:
    virtual ~HeaderBase(void);
    virtual u_int8_t* toString(void) = 0;
};


}
