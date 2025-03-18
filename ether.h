#pragma once

#define ETHER_ADDR_LEN 6

struct ethHdr
{
    uint8_t  dmac[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  smac[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
} __attribute__((__packed__));
