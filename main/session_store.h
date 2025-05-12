#pragma once
#include <stdint.h>
#include <stdbool.h>

/* opaque to main app */
typedef struct {
    uint8_t  DevAddr[4];
    uint8_t  NwkSKey[16];
    uint8_t  AppSKey[16];
    uint16_t FCnt;
} session_t;

/* initialise NVS (call once at boot) */
void session_nvs_init(void);

/* returns true  if a valid session was found and filled into *s
 * returns false if nothing stored  */
bool session_load(session_t *s);

/* saves / overwrites the current session  */
void session_save(const session_t *s);

/* wipe stored keys (e.g. for “re‑join” button)            */
void session_erase(void);
