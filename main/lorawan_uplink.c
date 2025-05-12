#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "lorawan_crypto.h"
#include "lorawan_uplink.h"

#define DIR_UP 0x00
static uint16_t fcnt = 0;               /* stays here – no extra params */
void lorawan_set_fcnt(uint16_t start) { fcnt = start; }
uint16_t lorawan_get_fcnt(void)       { return fcnt;  }

int lorawan_create_uplink(uint8_t       *out,
                          const uint8_t *payload,
                          size_t         len,
                          const uint8_t *DevAddr,
                          const uint8_t *NwkSKey,
                          const uint8_t *AppSKey)
{
    if (len > 51) return -1;            /* EU868 DR0 limit */

    uint8_t *p = out;
    *p++ = 0x80;                        /* MHDR = UnconfirmedDataUp      */
    memcpy(p, DevAddr, 4);  p += 4;
    *p++ = 0x00;                        /* FCtrl (FOptsLen = 0)          */
    *p++ = fcnt & 0xFF;  *p++ = fcnt >> 8;
    *p++ = 1;                           /* FPort = 1                     */

    /* ----- encrypt FRMPayload with AppSKey ----- */
    uint8_t S[16], a[16];
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, AppSKey, 128);

    for (size_t i = 0; i < len; ++i) {
        if ((i & 0x0F) == 0) {
            memset(a, 0, 16);
            a[0]  = 0x01;
            a[5]  = DIR_UP;
            memcpy(&a[6], DevAddr, 4);
            a[10] = fcnt & 0xFF;  a[11] = fcnt >> 8;
            a[15] = (i / 16) + 1;
            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, a, S);
        }
        p[i] = payload[i] ^ S[i & 0x0F];
    }
    mbedtls_aes_free(&aes);
    p += len;

    /* ----- MIC with NwkSKey ----- */
    size_t msgLen = p - out;
    uint8_t B0[16] = {0x49};
    B0[5]  = DIR_UP;
    memcpy(&B0[6], DevAddr, 4);
    B0[10] = fcnt & 0xFF;  B0[11] = fcnt >> 8;
    B0[15] = msgLen & 0xFF;

    uint8_t cmacBuf[272];
    memcpy(cmacBuf,      B0, 16);
    memcpy(cmacBuf + 16, out, msgLen);

    uint32_t mic = lorawan_aes_cmac(NwkSKey, cmacBuf, 16 + msgLen);
    *p++ = mic & 0xFF;  *p++ = mic >> 8;  *p++ = mic >> 16;  *p++ = mic >> 24;

    fcnt++;                             /* increment for next uplink     */
    return p - out;                     /* total length                  */
}
