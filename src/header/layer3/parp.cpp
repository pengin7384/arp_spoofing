#include "parp.h"

namespace pnetwork {

PArp::PArp() {
    data = new pnetwork_arp_header();
}

PArp::PArp(const u_int8_t* _arp_packet) {
    data = new pnetwork_arp_header();
    memcpy(data, _arp_packet, sizeof(pnetwork_arp_header));
}

PArp::~PArp() {
    delete data;
    data = nullptr;
}

u_int8_t* PArp::toString() {
    return reinterpret_cast<u_int8_t*>(data);
}


/* Getter */

u_int16_t PArp::getHardwareType() {
    return data->arp_header.ar_hrd;
}

u_int16_t PArp::getProtocolType() {
    return data->arp_header.ar_pro;
}

u_int8_t PArp::getHardwareSize() {
    return data->arp_header.ar_hln;
}

u_int8_t PArp::getProtocolSize() {
    return data->arp_header.ar_pln;
}

u_int16_t PArp::getOpCode() {
    return data->arp_header.ar_op;
}

void PArp::getSenderMac(u_int8_t* _sender_mac) {
    memcpy(_sender_mac, data->sender_mac, ETHER_ADDR_LEN);
}

u_int32_t PArp::getSenderIp() {
    return data->sender_ip;
}

void PArp::getTargetMac(u_int8_t* _target_mac) {
    memcpy(_target_mac, data->sender_mac, ETHER_ADDR_LEN);
}

u_int32_t PArp::getTargetIp() {
    return data->target_ip;
}


/* Setter */

void PArp::setHardwareType(u_int16_t _hdr_type) {
    data->arp_header.ar_hrd = _hdr_type;
}

void PArp::setProtocolType(u_int16_t _pro_type) {
    data->arp_header.ar_pro = _pro_type;
}

void PArp::setHardwareSize(u_int8_t _hdr_size) {
    data->arp_header.ar_hln = _hdr_size;
}

void PArp::setProtocolSize(u_int8_t _pro_size) {
    data->arp_header.ar_pln = _pro_size;
}

void PArp::setOpCode(u_int16_t _op_code) {
    data->arp_header.ar_op = _op_code;
}

void PArp::setSenderMac(u_int8_t* _sender_mac) {
    memcpy(data->sender_mac, _sender_mac, ETHER_ADDR_LEN);
}

void PArp::setSenderIp(u_int32_t _sender_ip) {
    data->sender_ip = _sender_ip;
}

void PArp::setTargetMac(u_int8_t* _target_mac) {
    memcpy(data->target_mac, _target_mac, ETHER_ADDR_LEN);
}

void PArp::setTargetIp(u_int32_t _target_ip) {
    data->target_ip = _target_ip;
}

}
