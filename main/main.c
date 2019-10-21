/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "cJSON.h"

#if CONFIG_SSL_USING_WOLFSSL
#include "lwip/apps/sntp.h"
#endif

#include "esp_tls.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID "miot_default"
#define EXAMPLE_WIFI_PASS "123456789x"

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "free-api.heweather.net"
#define WEB_PORT 443
#define WEB_URI "/s6/weather/now?location=auto_ip&key=f9e338e363254fb4b7ee272e62200cae"

static const char *TAG = "example";

static const char *REQUEST = "GET " WEB_URI " HTTP/1.0\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
    "\r\n";

/* Root cert for howsmyssl.com, taken from server_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");
    
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    /* For accessing reason codes in case of disconnection */
    system_event_info_t *info = &event->event_info;

    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        ESP_LOGE(TAG, "Disconnect reason : %d", info->disconnected.reason);
        if (info->disconnected.reason == WIFI_REASON_BASIC_RATE_NOT_SUPPORT) {
            /*Switch to 802.11 bgn mode */
            esp_wifi_set_protocol(ESP_IF_WIFI_STA, WIFI_PROTOCAL_11B | WIFI_PROTOCAL_11G | WIFI_PROTOCAL_11N);
        }
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

char strftime_buf[64];
void print_time()
{
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    //ESP_LOGI(TAG, "The current date/time in Shanghai is: %s", strftime_buf);
}

#if CONFIG_SSL_USING_WOLFSSL
static void get_time()
{
    struct timeval now;
    int sntp_retry_cnt = 0;
    int sntp_retry_time = 0;

    sntp_setoperatingmode(0);
    sntp_setservername(0, "cn.ntp.org.cn");
    sntp_setservername(1, "edu.ntp.org.cn");
    sntp_setservername(2, "us.ntp.org.cn");
    sntp_init();

    while (1) {
        for (int32_t i = 0; (i < (SNTP_RECV_TIMEOUT / 100)) && now.tv_sec < 1525952900; i++) {
            vTaskDelay(100 / portTICK_RATE_MS);
            gettimeofday(&now, NULL);
        }

        if (now.tv_sec < 1525952900) {
            sntp_retry_time = SNTP_RECV_TIMEOUT << sntp_retry_cnt;

            if (SNTP_RECV_TIMEOUT << (sntp_retry_cnt + 1) < SNTP_RETRY_TIMEOUT_MAX) {
                //sntp_retry_cnt ++;
            }

            printf("SNTP get time failed, retry after %d ms\n", sntp_retry_time);
            vTaskDelay(sntp_retry_time / portTICK_RATE_MS);
        } else 
        {
            printf("SNTP get time success\n");
            print_time();
            break;
        }
    }
}
#endif


static void https_get_task(void *pvParameters)
{
    char buf[2048] = { 0 };
    int ret, len;

    /* Wait for the callback to set the CONNECTED_BIT in the
    event group.
    */
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
    
    ESP_LOGI(TAG, "Connected to AP");

#if CONFIG_SSL_USING_WOLFSSL
    /* CA date verification need system time */
    get_time();
#endif



    esp_tls_cfg_t cfg = {
        .cacert_pem_buf  = server_root_cert_pem_start,
        .cacert_pem_bytes = server_root_cert_pem_end - server_root_cert_pem_start,
    };
    
    struct esp_tls *tls = esp_tls_conn_new(WEB_SERVER, strlen(WEB_SERVER), WEB_PORT, &cfg);
    
    if(tls != NULL) {
        ESP_LOGI(TAG, "Connection established...");
    } else {
        ESP_LOGE(TAG, "Connection failed...");
        goto exit;
    }
    
    size_t written_bytes = 0;
    do {
        ret = esp_tls_conn_write(tls, 
                                    REQUEST + written_bytes, 
                                    strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if
#if CONFIG_SSL_USING_MBEDTLS
        (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
#else
        (ret != WOLFSSL_ERROR_WANT_READ  && ret != WOLFSSL_ERROR_WANT_WRITE)
#endif
        {
            ESP_LOGE(TAG, "esp_tls_conn_write  returned 0x%x", ret);
            goto exit;
        }
    } while(written_bytes < strlen(REQUEST));

    ESP_LOGI(TAG, "Reading HTTP response...");

    char *read_buf = buf;

    len = sizeof(buf) - 1;

    do
    {
        len = 1024;
        ret = esp_tls_conn_read(tls, (char *)read_buf, len);

        if
#if CONFIG_SSL_USING_MBEDTLS
        (ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
#else
        (ret == WOLFSSL_ERROR_WANT_READ  && ret == WOLFSSL_ERROR_WANT_WRITE)
#endif
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(TAG, "esp_tls_conn_read  returned -0x%x", -ret);
            break;
        }

        if(ret == 0)
        {
            ESP_LOGI(TAG, "connection closed");
            break;
        }

        ESP_LOGI(TAG, "%d bytes read", ret);

        read_buf += ret;
        len -= ret;
    } while(1);

    read_buf = strstr(buf, "\r\n\r\n");

    cJSON *root = cJSON_Parse(read_buf);

    if(root != NULL)
    {
        //printf("\r\nokok\r\n");
        cJSON *HeWeather6 = cJSON_GetObjectItem(root,"HeWeather6");
        cJSON *array = cJSON_GetArrayItem(HeWeather6 , 0);
        cJSON *basic = cJSON_GetObjectItem(array,"basic");
        cJSON *now = cJSON_GetObjectItem(array,"now");

        cJSON *location = cJSON_GetObjectItem(basic,"location"); //城市

        cJSON *cond_txt = cJSON_GetObjectItem(now,"cond_txt");   //实况天气
        cJSON *wind_dir = cJSON_GetObjectItem(now,"wind_dir");   //风向
        cJSON *tmp = cJSON_GetObjectItem(now,"tmp");             //温度
        cJSON *fl = cJSON_GetObjectItem(now,"fl");               //体感温度
        cJSON *wind_sc = cJSON_GetObjectItem(now,"wind_sc");     //风力
        cJSON *hum = cJSON_GetObjectItem(now,"hum");             //相对湿度
        cJSON *pres = cJSON_GetObjectItem(now,"pres");            //气压

        print_time();

        printf("%s  %s\r\n", location -> valuestring, strftime_buf);

        printf("%s  %s  %s级\r\n", cond_txt -> valuestring, wind_dir -> valuestring, wind_sc -> valuestring);

        printf("温度:%s 体感:%s\r\n", tmp -> valuestring, fl -> valuestring);

        printf("气压:%s 相对湿度:%s\r\n", pres -> valuestring, hum -> valuestring);
    }

exit:
    esp_tls_conn_delete(tls);
    vTaskDelete(NULL);
}



void WS2812OutBuffer( char * buffer, uint16_t length );

void  ws2812_rest();

void app_main()
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    initialise_wifi();
    xTaskCreate(&https_get_task, "https_get_task", 8192 * 2, NULL, 5, NULL);
}
