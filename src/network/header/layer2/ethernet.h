#pragma once
#include "src/network/header/header_base.h"


namespace spoof {

class Ethernet : public HeaderBase {
    struct __attribute__((packed)) network_ethernet_header
    {
        uint8_t  ether_dhost[ETHER_ADDR_LEN];
        uint8_t  ether_shost[ETHER_ADDR_LEN];
        uint16_t ether_type;
    };

    network_ethernet_header *data;

public:
    Ethernet(void);
    Ethernet(const u_int8_t *ethernet_packet);
    ~Ethernet(void);

    virtual u_int8_t *toString(void);
    static size_t length(void)
    {
        return sizeof(network_ethernet_header);
    }

    /* Getter */
    void getDstMac(u_int8_t *dst_mac);
    void getSrcMac(u_int8_t *src_mac);
    u_int16_t getEtherType(void);

    /* Setter */
    void setDstMac(const u_int8_t *dst_mac);
    void setSrcMac(const u_int8_t *src_mac);
    void setEtherType(u_int16_t ether_type);

};

}
