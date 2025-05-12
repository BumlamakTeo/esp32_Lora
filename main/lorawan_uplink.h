#pragma once
#include <stddef.h>
#include <stdint.h>

/* builds an UnconfirmedDataUp (MHDR 0x40)
 * returns packet length, or <0 on error
 */
int lorawan_create_uplink(uint8_t       *out,
                          const uint8_t *payload,
                          size_t         len,
                          const uint8_t *DevAddr,
                          const uint8_t *NwkSKey,
                          const uint8_t *AppSKey);
void     lorawan_set_fcnt(uint16_t start);   /* seed counter after reboot   */
uint16_t lorawan_get_fcnt(void);             /* read back for NVS save      */