#pragma once
#include "src/header/pheaderbase.h"


namespace pnetwork {

class PEthernet : public PHeaderBase {
    struct __attribute__((packed)) pnetwork_ethernet
    {
        uint8_t  ether_dhost[ETHER_ADDR_LEN];
        uint8_t  ether_shost[ETHER_ADDR_LEN];
        uint16_t ether_type;
    };

    pnetwork_ethernet* data;

public:
    PEthernet();
    PEthernet(const u_int8_t* _ethernet_packet);
    ~PEthernet();

    virtual u_int8_t* toString();
    static size_t length() {
        return sizeof(pnetwork_ethernet);
    }

    /* Getter */
    void getDstMac(u_int8_t* _dst_mac);
    void getSrcMac(u_int8_t* _src_mac);
    u_int16_t getEtherType();

    /* Setter */
    void setDstMac(const u_int8_t* _dst_mac);
    void setSrcMac(const u_int8_t* _src_mac);
    void setEtherType(u_int16_t _ether_type);

};
}
