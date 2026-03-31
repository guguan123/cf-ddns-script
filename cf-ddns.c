/********************************************************************
 * cf-ddns.c
 * Cloudflare DDNS client supporting IPv4 / IPv6 / Dual-stack
 *
 * 编译: gcc -Wall -O2 cf-ddns.c -o cf-ddns -lcurl -lcjson
 *
 * 用法:
 *   ./cf-ddns [-4|-6|-46] <token> <zone_id> <record_name>
 *
 *   -4  : 只更新 A    (IPv4)
 *   -6  : 只更新 AAAA (IPv6)
 *   -46 : 双栈更新（默认）
 ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
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
		fprintf(stderr, "realloc() failed\n");
		return 0;
	}
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

// 获取当前公网 IP
static char* get_ip(CURL *curl, struct MemoryStruct *chunk, int family) {
	/* family: CURL_IPRESOLVE_V4 or CURL_IPRESOLVE_V6 */
	curl_easy_setopt(curl, CURLOPT_URL, "https://www.cloudflare.com/cdn-cgi/trace");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk);
	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, family);

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "trace fetch failed (%s): %s (HTTP %ld)\n",
				family == CURL_IPRESOLVE_V4 ? "IPv4" : "IPv6",
				curl_easy_strerror(res), http_code);
		return NULL;
	}

	char *line = strstr(chunk->memory, "ip=");
	if (!line) { free(chunk->memory); chunk->memory = NULL; chunk->size = 0; return NULL; }

	char *ip = strdup(line + 3);
	char *nl = strchr(ip, '\n');
	if (nl) *nl = 0;

	// 重置 chunk
	free(chunk->memory); chunk->memory = malloc(1); chunk->size = 0;

	return ip;
}

/* ------------------- DNS 记录操作 ------------------- */
typedef struct {
	char *id;
	char *content;
} DNSRecord;

static void free_dns_record(DNSRecord *r) {
	free(r->id);
	free(r->content);
	r->id = r->content = NULL;
}

// 获取 DNS 记录
static bool fetch_dns_record(const char *token, const char *zone_id,
							 const char *type, const char *name,
							 CURL *curl, struct MemoryStruct *chunk,
							 DNSRecord *rec) {
	memset(rec, 0, sizeof(*rec));

	char *enc_name = curl_easy_escape(curl, name, 0);
	if (!enc_name) return false;

	char url[512];
	snprintf(url, sizeof(url),
			 "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=%s&name=%s",
			 zone_id, type, enc_name);
	curl_free(enc_name);

	struct curl_slist *headers = NULL;
	char auth[256];
	snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
	headers = curl_slist_append(headers, auth);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk);

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "fetch %s record failed: %s (HTTP %ld)\n",
				type, curl_easy_strerror(res), http_code);
		return false;
	}

	cJSON *root = cJSON_Parse(chunk->memory);
	if (!root) {
		fprintf(stderr, "JSON parse error (%s)\n", type);
		return false;
	}
	free(chunk->memory); chunk->memory = malloc(1); chunk->size = 0;

	cJSON *result = cJSON_GetObjectItem(root, "result");
	if (!cJSON_IsArray(result) || cJSON_GetArraySize(result) == 0) {
		fprintf(stderr, "No %s record found for %s\n", type, name);
		cJSON_Delete(root);
		return false;
	}

	cJSON *first = cJSON_GetArrayItem(result, 0);
	cJSON *id = cJSON_GetObjectItem(first, "id");
	cJSON *content = cJSON_GetObjectItem(first, "content");

	if (id && id->valuestring) rec->id = strdup(id->valuestring);
	if (content && content->valuestring) rec->content = strdup(content->valuestring);

	cJSON_Delete(root);

	if (!rec->id || !rec->content) {
		fprintf(stderr, "Failed to parse %s record id/content\n", type);
		free_dns_record(rec);
		return false;
	}
	return true;
}

// 更新 DNS 记录
static bool update_dns_record(const char *token, const char *zone_id,
							  const char *type, const char *name,
							  const char *record_id, const char *new_ip,
							  CURL *curl, struct MemoryStruct *chunk) {
	char url[512];
	snprintf(url, sizeof(url),
			 "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
			 zone_id, record_id);

	// 使用 cJSON 构建结构化的 JSON 数据
	cJSON *root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "type", type);
	cJSON_AddStringToObject(root, "name", name);
	cJSON_AddStringToObject(root, "content", new_ip);
	cJSON_AddNumberToObject(root, "ttl", 300);
	cJSON_AddBoolToObject(root, "proxied", false);
	char *json_body = cJSON_PrintUnformatted(root);

	struct curl_slist *headers = NULL;
	char auth[256];
	snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
	headers = curl_slist_append(headers, auth);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, chunk);

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	free(json_body);
	curl_slist_free_all(headers);

	if (res != CURLE_OK || http_code != 200) {
		fprintf(stderr, "update %s failed: %s (HTTP %ld)\n",
				type, curl_easy_strerror(res), http_code);
		return false;
	}

	cJSON *root = cJSON_Parse(chunk->memory);
	free(chunk->memory); chunk->memory = malloc(1); chunk->size = 0;

	bool ok = false;
	if (root) {
		cJSON *success = cJSON_GetObjectItem(root, "success");
		ok = success && cJSON_IsTrue(success);
		cJSON_Delete(root);
	}

	if (ok) {
		printf("Updated %s → %s\n", type, new_ip);
	} else {
		fprintf(stderr, "API reports failure for %s\n", type);
	}
	return ok;
}

/* ------------------- 信号处理 ------------------- */
static volatile bool running = true;
static void sig_handler(int sig) { (void)sig; running = false; }

/* ------------------- 主程序 ------------------- */
int main(int argc, char *argv[]) {
	/* ---------- 解析参数 ---------- */
	bool do_v4 = false, do_v6 = false;
	int opt;
	while ((opt = getopt(argc, argv, "46")) != -1) {
		switch (opt) {
			case '4': do_v4 = true;  do_v6 = false; break;
			case '6': do_v6 = true;  do_v4 = false; break;
			default: /* 未知选项也视为双栈 */
				do_v4 = do_v6 = true; break;
		}
	}
	if (!do_v4 && !do_v6) do_v4 = do_v6 = true;  /* 默认双栈 */

	if (argc - optind != 3) {
		fprintf(stderr,
				"Usage: %s [-4|-6] <token> <zone_id> <record_name>\n"
				"   -4 : IPv4 only\n"
				"   -6 : IPv6 only\n"
				"   (default: both)\n", argv[0]);
		return 1;
	}

	const char *token       = argv[optind];
	const char *zone_id     = argv[optind + 1];
	const char *record_name = argv[optind + 2];

	/* ---------- 初始化 ---------- */
	curl_global_init(CURL_GLOBAL_ALL);
	CURL *curl = curl_easy_init();
	if (!curl) {
		perror("curl_easy_init");
		return 1;
	}

	struct MemoryStruct chunk = {
		.memory = malloc(1),
		.size = 0
	};
	if (!chunk.memory) {
		perror("malloc");
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return 1;
	}

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	/* ---------- 初始获取 DNS 记录 ---------- */
	DNSRecord rec_v4 = {0}, rec_v6 = {0};
	char *last_ip_v4 = NULL, *last_ip_v6 = NULL;

	if (do_v4) {
		if (!fetch_dns_record(token, zone_id, "A", record_name, curl, &chunk, &rec_v4)) {
			fprintf(stderr, "Failed to fetch initial A record\n");
			goto cleanup;
		}
		last_ip_v4 = strdup(rec_v4.content);
		printf("Initial A record: %s (id=%s)\n", last_ip_v4, rec_v4.id);
	}
	if (do_v6) {
		if (!fetch_dns_record(token, zone_id, "AAAA", record_name, curl, &chunk, &rec_v6)) {
			fprintf(stderr, "Failed to fetch initial AAAA record\n");
			goto cleanup;
		}
		last_ip_v6 = strdup(rec_v6.content);
		printf("Initial AAAA record: %s (id=%s)\n", last_ip_v6, rec_v6.id);
	}

	printf("DDNS monitor started (check every 5 min). Ctrl+C to stop.\n");

	/* ---------- 主循环 ---------- */
	while (running) {
		bool need_sleep = true;

		if (do_v4) {
			char *cur_ip = get_ip(curl, &chunk, CURL_IPRESOLVE_V4);
			if (cur_ip) {
				printf("Current IPv4: %s\n", cur_ip);
				if (!last_ip_v4 || strcmp(cur_ip, last_ip_v4) != 0) {
					printf("IPv4 changed %s → %s, updating...\n",
						   last_ip_v4 ? last_ip_v4 : "(none)", cur_ip);
					if (update_dns_record(token, zone_id, "A", record_name,
										  rec_v4.id, cur_ip, curl, &chunk)) {
						free(last_ip_v4);
						last_ip_v4 = cur_ip;
						cur_ip = NULL;
					}
				} else {
					printf("IPv4 unchanged.\n");
				}
				free(cur_ip);
				need_sleep = false;
			} else {
				fprintf(stderr, "Failed to get IPv4, will retry later.\n");
			}
		}

		if (do_v6) {
			char *cur_ip = get_ip(curl, &chunk, CURL_IPRESOLVE_V6);
			if (cur_ip) {
				printf("Current IPv6: %s\n", cur_ip);
				if (!last_ip_v6 || strcmp(cur_ip, last_ip_v6) != 0) {
					printf("IPv6 changed %s → %s, updating...\n",
						   last_ip_v6 ? last_ip_v6 : "(none)", cur_ip);
					if (update_dns_record(token, zone_id, "AAAA", record_name,
										  rec_v6.id, cur_ip, curl, &chunk)) {
						free(last_ip_v6);
						last_ip_v6 = cur_ip;
						cur_ip = NULL;
					}
				} else {
					printf("IPv6 unchanged.\n");
				}
				free(cur_ip);
				need_sleep = false;
			} else {
				fprintf(stderr, "Failed to get IPv6, will retry later.\n");
			}
		}

		if (need_sleep) sleep(60);   /* 任一 IP 获取失败时稍等再试 */
		else      sleep(300);        /* 正常检查间隔 5 分钟 */
	}

	printf("Shutting down.\n");

cleanup:
	free_dns_record(&rec_v4);
	free_dns_record(&rec_v6);
	free(last_ip_v4);
	free(last_ip_v6);
	free(chunk.memory);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return 0;
}
