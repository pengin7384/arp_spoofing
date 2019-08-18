#pragma once
#include "src/network/header/header_base.h"


namespace spoof {

class Arp : public HeaderBase {
    struct __attribute__((packed)) network_arp_header {
        libnet_arp_hdr arp_header;
        u_int8_t sender_mac[ETHER_ADDR_LEN];
        u_int32_t sender_ip;
        u_int8_t target_mac[ETHER_ADDR_LEN];
        u_int32_t target_ip;
    };

    network_arp_header *data;

public:

    Arp(void);
    Arp(const u_int8_t *arp_packet);
    ~Arp(void);

    virtual u_int8_t *toString(void);

    static size_t length(void)
    {
        return sizeof(network_arp_header);
    }

    /* Getter */
    u_int16_t getHardwareType(void);
    u_int16_t getProtocolType(void);
    u_int8_t getHardwareSize(void);
    u_int8_t getProtocolSize(void);
    u_int16_t getOpCode(void);
    void getSenderMac(u_int8_t *sender_mac);
    u_int32_t getSenderIp(void);
    void getTargetMac(u_int8_t *target_mac);
    u_int32_t getTargetIp(void);

    /* Setter */
    void setHardwareType(u_int16_t hdr_type);
    void setProtocolType(u_int16_t pro_type);
    void setHardwareSize(u_int8_t hdr_size);
    void setProtocolSize(u_int8_t pro_size);
    void setOpCode(u_int16_t op_code);
    void setSenderMac(u_int8_t *sender_mac);
    void setSenderIp(u_int32_t sender_ip);
    void setTargetMac(u_int8_t *target_mac);
    void setTargetIp(u_int32_t target_ip);
};

}
