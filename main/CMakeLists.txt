set(component_srcs "main.c")

idf_component_register(SRCS "session_store.c" "lorawan_uplink.c" "ra01s.c" "lorawan_crypto.c" "${component_srcs}"
                       INCLUDE_DIRS "."
                       REQUIRES esp_system mbedtls nvs_flash
                       PRIV_REQUIRES driver)
