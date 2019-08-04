#pragma once
#include <libnet.h>
#include "header/pheader.h"

namespace pnetwork {


/**
 * @brief The PPacketManager class
 * @details Process tasks related with packet
 */
class PPacketManager {

public:
    u_int8_t* buildARP(
            u_int8_t* _dst_mac,
            u_int8_t* _src_mac,
            u_int16_t _op_code,
            u_int8_t* _sender_mac,
            u_int32_t _sender_ip,
            u_int8_t* _target_mac,
            u_int32_t _target_ip);
    u_int16_t getEtherType(const u_int8_t* _packet);
    u_int32_t getArpSenderIp(const u_int8_t* _packet);
    void getArpSenderMac(const u_int8_t* _packet,  u_int8_t* _sender_mac);

};
}
