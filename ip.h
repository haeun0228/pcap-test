#pragma once
#define IP_LEN 4

struct ipHdr {
    uint8_t IHL:4;
    uint8_t version:4;
    uint8_t TOS;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t sip[IP_LEN];
    uint8_t dip[IP_LEN];
} __attribute__ ((__packed__));
