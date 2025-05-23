#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <time.h>
#include <linux/bpf.h>
#include <libbpf.h>

#define IP_ADDRESS(x) (unsigned int)(10 + (10 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3

struct backend_stats {
    __u32 cpu_percent;     // CPU 使用率 * 100
    __u32 avg_latency;     // 平均延遲 * 100
    __u64 last_updated;    // 最後更新時間 (ns)
    __u32 active_conns;    // 活躍連線數
};

struct response_data {
    char *data;
    size_t size;
};

// curl 回調函數
static size_t write_callback(void *contents, size_t size, size_t nmemb, struct response_data *response) {
    size_t total_size = size * nmemb;
    response->data = realloc(response->data, response->size + total_size + 1);
    if (response->data) {
        memcpy(&(response->data[response->size]), contents, total_size);
        response->size += total_size;
        response->data[response->size] = 0;
    }
    return total_size;
}

static __u64 time_get_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

// 從後端服務器獲取指標
int fetch_metrics(const char *backend_ip, struct backend_stats *stats) {
    CURL *curl;
    CURLcode res;
    struct response_data response = {0};
    char url[256];
    
    snprintf(url, sizeof(url), "http://%s/metrics", backend_ip);
    
    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 2 秒超時
    
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || !response.data) {
        if (response.data) free(response.data);
        return -1;
    }

    // 解析回應 (格式: cpu=XX.XX\nlatency=XX.XXms\n)
    float cpu_val = 0.0, latency_val = 0.0;
    char *line = strtok(response.data, "\n");
    
    while (line != NULL) {
        if (strncmp(line, "cpu=", 4) == 0) {
            cpu_val = atof(line + 4);
        } else if (strncmp(line, "latency=", 8) == 0) {
            latency_val = atof(line + 8);
            // 移除 "ms" 後綴
            char *ms_pos = strstr(line + 8, "ms");
            if (ms_pos) {
                *ms_pos = '\0';
                latency_val = atof(line + 8);
            }
        }
        line = strtok(NULL, "\n");
    }
    
    // 轉換為整數格式 (保留兩位小數)
    stats->cpu_percent = (__u32)(cpu_val * 100);
    stats->avg_latency = (__u32)(latency_val * 100);
    stats->last_updated = time_get_ns();
    // active_conns 由 XDP 程式維護，這裡不修改
    
    printf("Backend %s: CPU=%.2f%%, Latency=%.2fms\n", 
           backend_ip, cpu_val, latency_val);
    
    free(response.data);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int backend_stats_fd;
    int ret;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }

    // 初始化 curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // 載入 BPF 物件
    obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    // 獲取 backend_stats_m 的檔案描述符
    backend_stats_fd = bpf_object__find_map_fd_by_name(obj, "backend_stats_m");
    if (backend_stats_fd < 0) {
        fprintf(stderr, "ERROR: finding backend_stats_m failed\n");
        goto cleanup;
    }
    bpf_obj_pin(backend_stats_fd, "/sys/fs/bpf/backend_stats_m");

    int connection_map_fd = bpf_object__find_map_fd_by_name(obj, "connection_map");
    if (connection_map_fd < 0) {
        fprintf(stderr, "ERROR: finding connection_map failed\n");
        goto cleanup;
    }
    bpf_obj_pin(connection_map_fd, "/sys/fs/bpf/connection_map");

    printf("Starting metrics collection...\n");
    
    // 主循環：每 5 秒收集一次指標
    while (1) {
        struct backend_stats stats_a = {0}, stats_b = {0};
        __u32 backend_a_ip = IP_ADDRESS(BACKEND_A);
        __u32 backend_b_ip = IP_ADDRESS(BACKEND_B);
        bpf_map_update_elem(backend_stats_fd, &backend_a_ip, &stats_a, BPF_NOEXIST);
        bpf_map_update_elem(backend_stats_fd, &backend_b_ip, &stats_b, BPF_NOEXIST);
        
        // 獲取現有統計資料 (保留 active_conns)
        bpf_map_lookup_elem(backend_stats_fd, &backend_a_ip, &stats_a);
        bpf_map_lookup_elem(backend_stats_fd, &backend_b_ip, &stats_b);
        
        // 從後端 A 獲取指標
        if (fetch_metrics("10.10.0.2", &stats_a) == 0) {
            ret = bpf_map_update_elem(backend_stats_fd, &backend_a_ip, &stats_a, BPF_ANY);
            if (ret != 0) {
                printf("Failed to update stats for backend A: %d\n", ret);
            }
        } else {
            printf("Failed to fetch metrics from backend A\n");
        }
        
        // 從後端 B 獲取指標
        if (fetch_metrics("10.10.0.3", &stats_b) == 0) {
            ret = bpf_map_update_elem(backend_stats_fd, &backend_b_ip, &stats_b, BPF_ANY);
            if (ret != 0) {
                printf("Failed to update stats for backend B: %d\n", ret);
            }
        } else {
            printf("Failed to fetch metrics from backend B\n");
        }
        
        printf("Active connections - A: %u, B: %u\n", 
               stats_a.active_conns, stats_b.active_conns);
        printf("---\n");
        
        sleep(5);
    }

cleanup:
    bpf_object__close(obj);
    curl_global_cleanup();
    return 0;
}
