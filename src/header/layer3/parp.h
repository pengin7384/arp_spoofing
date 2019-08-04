#pragma once
#include "src/header/pheaderbase.h"


namespace pnetwork {
class PArp : public PHeaderBase {
    struct __attribute__((packed)) pnetwork_arp_header {
        libnet_arp_hdr arp_header;
        u_int8_t sender_mac[ETHER_ADDR_LEN];
        u_int32_t sender_ip;
        u_int8_t target_mac[ETHER_ADDR_LEN];
        u_int32_t target_ip;
    };

    pnetwork_arp_header* data;

public:

    PArp();
    PArp(const u_int8_t* _arp_packet);
    ~PArp();

    virtual u_int8_t* toString();

    static size_t length() {
        return sizeof(pnetwork_arp_header);
    }

    /* Getter */
    u_int16_t getHardwareType();
    u_int16_t getProtocolType();
    u_int8_t getHardwareSize();
    u_int8_t getProtocolSize();
    u_int16_t getOpCode();
    void getSenderMac(u_int8_t* _sender_mac);
    u_int32_t getSenderIp();
    void getTargetMac(u_int8_t* _target_mac);
    u_int32_t getTargetIp();

    /* Setter */
    void setHardwareType(u_int16_t _hdr_type);
    void setProtocolType(u_int16_t _pro_type);
    void setHardwareSize(u_int8_t _hdr_size);
    void setProtocolSize(u_int8_t _pro_size);
    void setOpCode(u_int16_t _op_code);
    void setSenderMac(u_int8_t* _sender_mac);
    void setSenderIp(u_int32_t _sender_ip);
    void setTargetMac(u_int8_t* _target_mac);
    void setTargetIp(u_int32_t _target_ip);
};


}
