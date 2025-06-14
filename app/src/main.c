#include <stdio.h>
#include "zephyr/net/http/server.h"

#include <zephyr/net/http/service.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_http_server_sample, LOG_LEVEL_DBG);

static uint16_t http_service_port = 1919;

HTTP_SERVICE_DEFINE(homo, NULL, &http_service_port, 1, 10, NULL, NULL);

static int dyn_handler(struct http_client_ctx *client, enum http_data_status status,
			const struct http_request_ctx *request_ctx,
			struct http_response_ctx *response_ctx, void *user_data)
{
#define MAX_TEMP_PRINT_LEN 32
	static char print_str[MAX_TEMP_PRINT_LEN];
	enum http_method method = client->method;
	static size_t processed;

	if (status == HTTP_SERVER_DATA_ABORTED) {
		LOG_DBG("Transaction aborted after %zd bytes.", processed);
		processed = 0;
		return 0;
	}

	__ASSERT_NO_MSG(buffer != NULL);

	processed += request_ctx->data_len;

	snprintf(print_str, sizeof(print_str), "%s received (%zd bytes)", http_method_str(method),
		 request_ctx->data_len);
	LOG_HEXDUMP_DBG(request_ctx->data, request_ctx->data_len, print_str);

	if (status == HTTP_SERVER_DATA_FINAL) {
		LOG_DBG("All data received (%zd bytes).", processed);
		processed = 0;
	}

	/* Echo data back to client */
	response_ctx->body = request_ctx->data;
	response_ctx->body_len = request_ctx->data_len;
	response_ctx->final_chunk = (status == HTTP_SERVER_DATA_FINAL);

	return 0;
}

struct http_resource_detail_dynamic dyn_resource_detail = {
    .common = {
        .type = HTTP_RESOURCE_TYPE_DYNAMIC,
        .bitmask_of_supported_http_methods =
            BIT(HTTP_GET) | BIT(HTTP_POST),
    },
    .cb = dyn_handler,
    .user_data = NULL,
};

HTTP_RESOURCE_DEFINE(dyn_resource, homo, "/dynamic",
                     &dyn_resource_detail);


int main(void)
{
    http_server_start();
}