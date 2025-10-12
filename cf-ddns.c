#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <ctype.h>
#include <cjson/cJSON.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

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

// 获取当前公网 IPv4 地址
static char* get_current_ip(CURL *curl, struct MemoryStruct *chunk) {
	char* current_ip = NULL;
	long http_code = 0;
	CURLcode res;

	curl_easy_setopt(curl, CURLOPT_URL, "https://www.cloudflare.com/cdn-cgi/trace");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);
	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);   /* 强制 IPv4 */

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "Trace fetch failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		return NULL;
	}

	// 从返回文本中解析 ip= 行
	char* ip_line = strstr(chunk->memory, "ip=");
	if (ip_line) {
		// 跳过 "ip="
		current_ip = strdup(ip_line + 3);
		char* nl = strchr(current_ip, '\n');
		// 去掉换行
		if (nl) *nl = 0;
	}

	// 重置 chunk
	free(chunk->memory);
	chunk->memory = malloc(1);
	if (!chunk->memory) {
		// 如果无法分配内存
		fprintf(stderr, "Re-malloc failed in get_current_ip\n");
	}
	chunk->size = 0;

	// 简单 IPv4 校验
	if (!current_ip || !strchr(current_ip, '.')) {
		fprintf(stderr, "Failed to get valid IP\n");
		free(current_ip);
		return NULL;
	}

	return current_ip;
}

// 获取 DNS 记录的 ID 和当前 IP
static bool get_dns_record(const char* token, const char* zone_id, const char* record_name,
                           CURL *curl, struct MemoryStruct *chunk, char** record_id, char** dns_ip) {
	long http_code = 0;
	CURLcode res;
	struct curl_slist *headers = NULL;
	char auth_header[256];

	char* encoded_name = url_encode(record_name);
	if (!encoded_name) {
		fprintf(stderr, "URL encode failed\n");
		return false;
	}
	char url[256];
	snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", zone_id, encoded_name);
	free(encoded_name);

	snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	// 清除 cURL 句柄内部的指针，避免悬空引用
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "DNS fetch failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		return false;
	}

	// 使用 cJSON 解析返回内容
	cJSON *root = cJSON_Parse(chunk->memory);

	// 重置 chunk
	free(chunk->memory);
	chunk->memory = malloc(1);
	if (!chunk->memory) {
		// 如果无法分配内存
		fprintf(stderr, "Re-malloc failed in get_current_ip\n");
	}
	chunk->size = 0;

	// cJSON 解析内容失败
	if (!root) {
		fprintf(stderr, "JSON parse failed for DNS records\n");
		return false;
	}
	cJSON *result = cJSON_GetObjectItem(root, "result");
	if (!cJSON_IsArray(result) || cJSON_GetArraySize(result) == 0) {
		fprintf(stderr, "No DNS record found\n");
		cJSON_Delete(root);
		return false;
	}
	cJSON *rec = cJSON_GetArrayItem(result, 0); /* 默认取第一条 */
	cJSON *id_obj = cJSON_GetObjectItem(rec, "id");
	cJSON *content_obj = cJSON_GetObjectItem(rec, "content");
	*record_id = id_obj->valuestring ? strdup(id_obj->valuestring) : NULL;
	*dns_ip = content_obj->valuestring ? strdup(content_obj->valuestring) : NULL;
	cJSON_Delete(root);

	if (!*record_id || !*dns_ip) {
		fprintf(stderr, "Failed to parse record ID or content\n");
		return false;
	}

	return true;
}

// 更新 DNS 记录
static bool update_dns_record(const char* token, const char* zone_id, const char* record_name,
                              const char* record_id, const char* new_ip,
                              CURL *curl, struct MemoryStruct *chunk) {
	long http_code = 0;
	CURLcode res;
	struct curl_slist *headers = NULL;
	char auth_header[256];

	char put_url[256];
	snprintf(put_url, sizeof(put_url), "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zone_id, record_id);

	char* escaped_name = json_escape(record_name);
	if (!escaped_name) {
		fprintf(stderr, "JSON escape failed\n");
		return false;
	}
	char* escaped_ip = json_escape(new_ip);
	if (!escaped_ip) {
		fprintf(stderr, "JSON escape failed\n");
		free(escaped_name);
		return false;
	}
	char json_body[512];
	snprintf(json_body, sizeof(json_body),
			 "{\"type\":\"A\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":300,\"proxied\":false}",
			 escaped_name, escaped_ip);
	free(escaped_name);
	free(escaped_ip);

	snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);
	headers = curl_slist_append(headers, auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, put_url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	// 清除 cURL 句柄内部的指针，避免悬空引用
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, NULL);
	curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "Update failed: %s (HTTP %ld)\n", curl_easy_strerror(res), http_code);
		return false;
	}

	// 再次用 cJSON 判断更新是否成功
	cJSON *update_root = cJSON_Parse(chunk->memory);

	// 重置 chunk
	free(chunk->memory);
	chunk->memory = malloc(1);
	if (!chunk->memory) {
		fprintf(stderr, "Re-malloc failed in get_current_ip\n");
	}
	chunk->size = 0;

	if (!update_root) {
		fprintf(stderr, "JSON parse failed for update response\n");
		return false;
	}
	cJSON *success_obj = cJSON_GetObjectItem(update_root, "success");
	bool success = (success_obj != NULL && cJSON_IsTrue(success_obj));
	cJSON_Delete(update_root);

	if (success) {
		printf("DNS updated to %s (TTL 300)\n", new_ip);
	} else {
		fprintf(stderr, "Update API error: %s\n", chunk->memory);
	}

	return success;
}

// 信号处理：优雅退出
static volatile bool running = true;
static void signal_handler(int sig) {
	(void)sig;
	running = false;
}

int main(void) {
	CURL *curl;
	CURLcode res;
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
	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl_easy_init() failed\n");
		curl_global_cleanup();
		free(chunk.memory);
		return 1;
	}

	// 注册信号处理
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// 初始获取 DNS 当前 IP
	char *record_id = NULL;
	char *last_ip = NULL;
	if (!get_dns_record(token, zone_id, record_name, curl, &chunk, &record_id, &last_ip)) {
		fprintf(stderr, "Initial DNS fetch failed\n");
		goto cleanup;
	}
	printf("Initial DNS IP: %s\n", last_ip);

	printf("Starting DDNS monitor loop (check every 5 minutes). Press Ctrl+C to stop.\n");

	// 主循环：每 300 秒检查一次 IP 变化
	while (running) {
		char *current_ip = get_current_ip(curl, &chunk);
		if (!current_ip) {
			fprintf(stderr, "Failed to get current IP, skipping...\n");
			sleep(300);
			continue;
		}

		printf("Current IP: %s\n", current_ip);

		// 判断是否需要更新
		if (strcmp(current_ip, last_ip) != 0) {
			printf("IP changed from %s to %s. Updating DNS...\n", last_ip, current_ip);
			if (update_dns_record(token, zone_id, record_name, record_id, current_ip, curl, &chunk)) {
				free(last_ip);
				last_ip = current_ip;
				current_ip = NULL; // 立即置空指针，防止双重释放
			} else {
				fprintf(stderr, "Update failed, keeping old IP.\n");
				free(current_ip);
				current_ip = NULL; // 置空指针
			}
		} else {
			printf("IP unchanged. No update needed.\n");
			free(current_ip);
		}

		sleep(300);  // 5 分钟检查一次
	}

	printf("Shutting down DDNS monitor.\n");

cleanup:
	free(record_id);
	free(last_ip);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return 0;
}
