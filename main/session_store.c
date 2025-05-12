#include "session_store.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

#define TAG      "SESSION"
#define NVS_NS   "lorawan"         /* namespace   */
#define NVS_KEY  "state"           /* blob name   */
#define MAGIC    0x51FA1234        /* sanity mark */

typedef struct {
    uint32_t magic;                /* must be MAGIC */
    session_t s;                   /* real payload  */
} blob_t;

/* ——— public API ——————————————————————————————— */
void session_nvs_init(void)
{
    static bool done = false;
    if (!done) { ESP_ERROR_CHECK(nvs_flash_init()); done = true; }
}

static esp_err_t open_rw(nvs_handle_t *h, nvs_open_mode mode)
{
    return nvs_open(NVS_NS, mode, h);
}

bool session_load(session_t *out)
{
    nvs_handle_t h;
    blob_t blob;
    size_t len = sizeof blob;

    if (open_rw(&h, NVS_READONLY) != ESP_OK)           return false;
    if (nvs_get_blob(h, NVS_KEY, &blob, &len) != ESP_OK) { nvs_close(h); return false; }
    nvs_close(h);

    if (len != sizeof blob || blob.magic != MAGIC)     return false;
    *out = blob.s;
    ESP_LOGI(TAG, "restored session (FCnt=%u)", out->FCnt);
    return true;
}

void session_save(const session_t *in)
{
    nvs_handle_t h;
    blob_t blob = { .magic = MAGIC, .s = *in };

    if (open_rw(&h, NVS_READWRITE) != ESP_OK)          return;
    nvs_set_blob(h, NVS_KEY, &blob, sizeof blob);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "session saved (FCnt=%u)", in->FCnt);
}

void session_erase(void)
{
    nvs_handle_t h;
    if (open_rw(&h, NVS_READWRITE) != ESP_OK)          return;
    nvs_erase_key(h, NVS_KEY);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "stored session ERASED");
}
