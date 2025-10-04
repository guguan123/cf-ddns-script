#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <ctype.h>
#include <cjson/cJSON.h>

// 用于保存 HTTP 响应数据的内存块
struct MemoryStruct {
	char *memory;   /* 实际数据指针 */
	size_t size;    /* 已用字节数 */
};

// libcurl 回调：将下载到的内容追加到 MemoryStruct 中
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		fprintf(stderr, "Not enough memory, realloc() failed\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	// 追加字符串结束符
	mem->memory[mem->size] = 0;

	return realsize;
}

// 简易 URL 编码：仅针对域名或 IP 等基本字符
static char* url_encode(const char* str) {
	char *encoded = malloc(strlen(str) * 3 + 1);
	if (!encoded) return NULL;
	char *p = encoded;
	for (const char *s = str; *s; s++) {
		if (isalnum(*s) || *s == '-' || *s == '_' || *s == '.' || *s == '~') {
			*p++ = *s;
		} else {
			sprintf(p, "%%%02X", (unsigned char)*s);
			p += 3;
		}
	}
	*p = 0;
	return encoded;
}

// 简易 JSON 字符串转义：仅处理双引号与反斜杠
static char* json_escape(const char* str) {
	size_t len = strlen(str);
	char* escaped = malloc(len * 2 + 1); // 最坏情况：全部字符均需转义
	if (!escaped) return NULL;
	char* p = escaped;
	for (const char* s = str; *s; s++) {
		if (*s == '"' || *s == '\\') {
			*p++ = '\\';
			*p++ = *s;
		} else {
			*p++ = *s;
		}
	}
	*p = 0;
	return escaped;
}

int main(void) {
	CURL *curl;
	CURLcode res;
	long http_code = 0;
	int ret = 1;   /* 返回值：0 成功，1 失败 */
	struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };
	if (!chunk.memory) {
		fprintf(stderr, "malloc() 失败\n");
		return 1;
	}

	// Cloudflare API Token
	const char* token     = "";
	// 区域 ID
	const char* zone_id   = "";
	// 要更新的域名
	const char* record_name = "";

	if (!token || !zone_id || !record_name) {
		fprintf(stderr, "Missing config\n");
		free(chunk.memory);
		return 1;
	}

	curl_global_init(CURL_GLOBAL_ALL);

	// 步骤 1：通过 Cloudflare trace 接口获取当前公网 IPv4
	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl_easy_init() failed\n");
		curl_global_cleanup();
		free(chunk.memory);
		return 1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, "https://www.cloudflare.com/cdn-cgi/trace");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);   /* 强制 IPv4 */

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "Trace fetch failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		curl_global_cleanup();
		free(chunk.memory);
		return 1;
	}

	// 从返回文本中解析 ip= 行
	char* current_ip = NULL;
	char* ip_line = strstr(chunk.memory, "ip=");
	if (ip_line) {
		// 跳过 "ip="
		current_ip = strdup(ip_line + 3);
		char* nl = strchr(current_ip, '\n');
		// 去掉换行
		if (nl) *nl = 0;
	}
	// 重置 chunk，供后续请求复用
	free(chunk.memory);
	chunk.memory = malloc(1);
	chunk.size = 0;

	// 简单 IPv4 校验
	if (!current_ip || !strchr(current_ip, '.')) {
		fprintf(stderr, "Failed to get valid IP\n");
		goto cleanup;
	}
	printf("Current IP: %s\n", current_ip);

	// 步骤 2：获取指定域名的 DNS 记录 ID 及当前解析值
	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl_easy_init() failed\n");
		goto cleanup;
	}

	char* encoded_name = url_encode(record_name);
	if (!encoded_name) {
		fprintf(stderr, "URL encode failed\n");
		curl_easy_cleanup(curl);
		goto cleanup;
	}
	char url[256];
	snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", zone_id, encoded_name);
	free(encoded_name);

	struct curl_slist *headers = NULL;
	char auth_header[256];
	snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "DNS fetch failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		goto cleanup;
	}

	// 使用 cJSON 解析返回内容
	cJSON *root = cJSON_Parse(chunk.memory);
	if (!root) {
		fprintf(stderr, "JSON parse failed for DNS records\n");
		goto cleanup;
	}
	cJSON *result = cJSON_GetObjectItem(root, "result");
	if (!cJSON_IsArray(result) || cJSON_GetArraySize(result) == 0) {
		fprintf(stderr, "No DNS record found\n");
		cJSON_Delete(root);
		goto cleanup;
	}
	cJSON *rec = cJSON_GetArrayItem(result, 0); /* 默认取第一条 */
	cJSON *id_obj = cJSON_GetObjectItem(rec, "id");
	cJSON *content_obj = cJSON_GetObjectItem(rec, "content");
	char* record_id = id_obj->valuestring ? strdup(id_obj->valuestring) : NULL;
	char* dns_ip = content_obj->valuestring ? strdup(content_obj->valuestring) : NULL;
	cJSON_Delete(root);

	if (!record_id || !dns_ip) {
		fprintf(stderr, "Failed to parse record ID or content\n");
		goto cleanup;
	}
	printf("DNS Record ID: %s\n", record_id);
	printf("Current DNS IP: %s\n", dns_ip);

	// 步骤 3：判断是否需要更新
	if (strcmp(current_ip, dns_ip) == 0) {
		printf("IP unchanged. No update needed.\n");
		free(record_id);
		free(dns_ip);
		ret = 0; /* 同样视为成功 */
		goto cleanup;
	}
	free(dns_ip);

	// 重置 chunk，供步骤 4 复用
	free(chunk.memory);
	chunk.memory = malloc(1);
	chunk.size = 0;

	// 步骤 4：调用 Cloudflare API 更新 DNS 记录
	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl_easy_init() failed\n");
		free(record_id);
		goto cleanup;
	}

	char put_url[256];
	snprintf(put_url, sizeof(put_url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zone_id, record_id);
	free(record_id); /* 后续不再需要 */

	char* escaped_name = json_escape(record_name);
	if (!escaped_name) {
		fprintf(stderr, "JSON escape failed\n");
		curl_easy_cleanup(curl);
		goto cleanup;
	}
	char* escaped_ip = json_escape(current_ip);
	if (!escaped_ip) {
		fprintf(stderr, "JSON escape failed\n");
		free(escaped_name);
		curl_easy_cleanup(curl);
		goto cleanup;
	}
	char json_body[512];
	snprintf(json_body, sizeof(json_body),
			 "{\"type\":\"A\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":300,\"proxied\":false}",
			 escaped_name, escaped_ip);
	free(escaped_name);
	free(escaped_ip);

	headers = NULL;
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, put_url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "Update failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		goto cleanup;
	}

	// 再次用 cJSON 判断更新是否成功
	cJSON *update_root = cJSON_Parse(chunk.memory);
	if (!update_root) {
		fprintf(stderr, "JSON parse failed for update response\n");
		goto cleanup;
	}
	cJSON *success_obj = cJSON_GetObjectItem(update_root, "success");
	if (success_obj != NULL && cJSON_IsTrue(success_obj)) {
		printf("DNS updated to %s (TTL 300)\n", current_ip);
		ret = 0; /* 标记为成功 */
	} else {
		fprintf(stderr, "Update API error: %s\n", chunk.memory);
	}
	cJSON_Delete(update_root);

cleanup:
	free(current_ip);
	free(chunk.memory);
	curl_global_cleanup();
	return ret;
}
