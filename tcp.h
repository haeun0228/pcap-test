#pragma once

struct tcpHdr
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved:4;
    uint8_t data_offset:4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;

} __attribute__ ((__packed__));

