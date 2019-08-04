#pragma once
#include <sys/types.h>
#include <libnet.h>

namespace pnetwork {
class PHeaderBase {


public:
    virtual ~PHeaderBase();
    virtual u_int8_t* toString() = 0;
};


}
