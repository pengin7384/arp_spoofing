#include "pethernet.h"

namespace pnetwork {

PEthernet::PEthernet() {
    data = new pnetwork_ethernet();
}

PEthernet::PEthernet(const u_int8_t* _ethernet_packet) {
    data = new pnetwork_ethernet();
    memcpy(data, _ethernet_packet, sizeof(pnetwork_ethernet));
}

PEthernet::~PEthernet() {
    delete data;
}

u_int8_t* PEthernet::toString() {
    return reinterpret_cast<u_int8_t*>(data);
}

/* Getter */

void PEthernet::getDstMac(u_int8_t* _dst_mac) {
    memcpy(_dst_mac, data->ether_dhost, ETHER_ADDR_LEN);
}

void PEthernet::getSrcMac(u_int8_t* _src_mac) {
    memcpy(_src_mac, data->ether_shost, ETHER_ADDR_LEN);
}

u_int16_t PEthernet::getEtherType() {
    return data->ether_type;
}


/* Setter */

void PEthernet::setDstMac(const u_int8_t* _dst_mac) {
    memcpy(data->ether_dhost, _dst_mac, ETHER_ADDR_LEN);
}

void PEthernet::setSrcMac(const u_int8_t* _src_mac) {
    memcpy(data->ether_shost, _src_mac, ETHER_ADDR_LEN);
}

void PEthernet::setEtherType(u_int16_t _ether_type) {
    data->ether_type = _ether_type;
}
}
