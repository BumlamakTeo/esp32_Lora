/* app_main.c – LoRaWAN OTAA join + uplink example for ESP32‑S3 + SX1261
 *
 *  – Uses ra01s driver (nopnop2002) + mbedTLS for AES/CMAC
 *  – Sends JoinRequest, waits for JoinAccept, then transmits encrypted uplinks
 *  – Region: EU868, 868.1 MHz, SF7BW125, CR4/5
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <inttypes.h>
 #include <time.h>
 
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "esp_log.h"
 
 #include "ra01s.h"             // SX126x driver
 #include "lorawan_crypto.h"    // AES‑CMAC & AES‑ECB helpers
 #include "session_store.h"
 #include "lorawan_uplink.h"    // helper we generate below
 
 static const char *TAG = "OTAA_LORA";
 static session_t g;           /* DevAddr, keys, FCnt */
 
 //--------------------------------------------------------------------
 // 1) Static LoRaWAN identifiers  (⚠️  ChirpStack expects MSB order)
 //--------------------------------------------------------------------
 static const uint8_t DevEUI[8]  = {0x08,0x07,0x06,0x05,  0x04,0x03,0x02,0x01};
 static const uint8_t JoinEUI[8] = {0x01,0x01,0x01,0x01,  0x01,0x01,0x01,0x01};
 static const uint8_t AppKey[16] = {0x01,0x02,0x03,0x04,  0x05,0x06,0x07,0x08,
									0x09,0x0A,0x0B,0x0C,  0x0D,0x0E,0x0F,0x10};
 
 // Will be filled after join
 static uint8_t DevAddr[4];
 static uint8_t NwkSKey[16], AppSKey[16];
 static uint8_t DevNonce[2];
 
 //--------------------------------------------------------------------
 // 2) Build + send a JoinRequest frame
 //--------------------------------------------------------------------
 static void send_join_request(void)
 {
	 uint8_t buf[23];
	 buf[0] = 0x00;                       // MHDR = JoinRequest
	 memcpy(&buf[1],  JoinEUI, 8);        // JoinEUI (LSB)
	 memcpy(&buf[9],  DevEUI,  8);        // DevEUI  (LSB)
 
	 // Random DevNonce (NOT cryptographically secure – replace rand() later!)
	 DevNonce[0] = rand() & 0xFF;
	 DevNonce[1] = rand() & 0xFF;
	 buf[17] = DevNonce[0];
	 buf[18] = DevNonce[1];
 
	 uint32_t mic = lorawan_aes_cmac(AppKey, buf, 19);
	 buf[19] = (mic      ) & 0xFF;
	 buf[20] = (mic >>  8) & 0xFF;
	 buf[21] = (mic >> 16) & 0xFF;
	 buf[22] = (mic >> 24) & 0xFF;
 
	 ESP_LOG_BUFFER_HEXDUMP(TAG, buf, sizeof(buf), ESP_LOG_INFO);
	 ESP_LOGI(TAG, "Sending JoinRequest, DevNonce=0x%02X%02X", DevNonce[1], DevNonce[0]);
	 LoRaSend(buf, sizeof(buf), SX126x_TXMODE_SYNC);
 }
 
 //--------------------------------------------------------------------
 // 3) Wait for JoinAccept & derive session keys
 //--------------------------------------------------------------------
 static bool receive_join_accept(void)
 {
	 vTaskDelay(pdMS_TO_TICKS(5000));          // RX1 delay 5 s
 
	 uint8_t rx[256];
	 int16_t len = LoRaReceive(rx, sizeof(rx));
	 if (len <= 0) {
		 ESP_LOGW(TAG, "No JoinAccept received");
		 return false;
	 }
 
	 if (len < 17 || (rx[0] & 0xE0) != 0x20) {
		 ESP_LOGE(TAG, "Invalid JoinAccept frame");
		 return false;
	 }
 
	 // Decrypt JoinAccept payload (AES‑128 ECB with AppKey)
	 uint8_t plaintext[16] = {0};
	 aes128_encrypt(AppKey, &rx[1], plaintext);   // first 16 B only (CFList ignored)
 
	 uint8_t *p = plaintext;
	 uint8_t AppNonce[3], NetID[3];
	 memcpy(AppNonce, p, 3);  p += 3;
	 memcpy(NetID,    p, 3);  p += 3;
	 memcpy(DevAddr,  p, 4);  p += 4;
 
	 ESP_LOGI(TAG, "AppNonce=%02X%02X%02X  NetID=%02X%02X%02X  DevAddr=%02X%02X%02X%02X",
			  AppNonce[2],AppNonce[1],AppNonce[0], NetID[2],NetID[1],NetID[0],
			  DevAddr[3],DevAddr[2],DevAddr[1],DevAddr[0]);
 
	 uint8_t tmp[16] = {0};
	 // NwkSKey = cmac(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad)
	 tmp[0] = 0x01;
	 memcpy(&tmp[1],  AppNonce, 3);
	 memcpy(&tmp[4],  NetID,    3);
	 memcpy(&tmp[7],  DevNonce, 2);
	 aes128_encrypt(AppKey, tmp, NwkSKey);
 
	 // AppSKey = cmac(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad)
	 tmp[0] = 0x02;
	 aes128_encrypt(AppKey, tmp, AppSKey);
 
	 ESP_LOGI(TAG, "Session keys derived – join complete");
	 return true;
 }
 
 //--------------------------------------------------------------------
 // 4) Build + send encrypted uplinks
 //--------------------------------------------------------------------

 
 static void task_tx(void *pv)
 {
	 ESP_LOGI(TAG, ">>> Uplink task started");
	 uint8_t pkt[64];
	 while (1) {
		char json[] = "{\"temp\":24.8,\"hum\":55}";
		int len = lorawan_create_uplink(pkt,
										(uint8_t*)json, strlen(json),
										DevAddr, NwkSKey, AppSKey);
		if (LoRaSend(pkt, len, SX126x_TXMODE_SYNC)) {
             /* pull updated counter from builder & persist */
             g.FCnt = lorawan_get_fcnt();
             session_save(&g);
         }
		vTaskDelay(pdMS_TO_TICKS(30000));
	 }
 }
 
 //--------------------------------------------------------------------
 // 5) Entry point
 //--------------------------------------------------------------------
 void app_main(void)
 {	
	session_nvs_init();
	srand((unsigned int)time(NULL));
 
	 // Init SX126x & driver
	 LoRaInit();
	 LoRaDebugPrint(true);              // verbose logs
 
	 if (LoRaBegin(868100000, 22, 3.3f, true) != ERR_NONE) {
		 ESP_LOGE(TAG, "LoRaBegin failed – check wiring");
		 return;
	 }
	 SetSyncWord(0x3444);
 
	 LoRaConfig(7, 4, 1, 8, 0, true, false); // SF7/BW125/CR4‑5
 
	/* ---------- try to resume previous session ---------- */
     bool have = session_load(&g);
     if (have) {
         memcpy(DevAddr, g.DevAddr, 4);
         memcpy(NwkSKey, g.NwkSKey, 16);
         memcpy(AppSKey, g.AppSKey, 16);
         lorawan_set_fcnt(g.FCnt);                /* seed uplink builder */
     } else {
         /* ---------- fresh OTAA join ---------- */
         for (int attempt = 0; attempt < 3; ++attempt) {
             ESP_LOGI(TAG, "OTAA attempt %d", attempt + 1);
             LoRaConfig(7,4,1,8,0,true,false);
             send_join_request();
             LoRaConfig(7,4,1,8,0,true,true);
             if (receive_join_accept()) break;
         }
         LoRaConfig(7,4,1,8,0,true,false);        /* back to normal IQ */
         if (DevAddr[0]==0 && DevAddr[1]==0 && DevAddr[2]==0 && DevAddr[3]==0) {
             ESP_LOGE(TAG, "OTAA failed – reboot to retry");
             return;
         }
         /* store the fresh keys */
         memcpy(g.DevAddr, DevAddr, 4);
         memcpy(g.NwkSKey, NwkSKey, 16);
         memcpy(g.AppSKey, AppSKey, 16);
         g.FCnt = 0;
         session_save(&g);
     }
 
	 // Start periodic uplink task
	 xTaskCreate(task_tx, "tx", 4096, NULL, 5, NULL);
 }