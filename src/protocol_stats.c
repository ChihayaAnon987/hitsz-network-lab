#include "protocol_stats.h"
#include <stdio.h>
#include <inttypes.h>

/**
 * @brief 全局统计数据初始化
 */
protocol_stats_t ip_stats = {0};
protocol_stats_t tcp_stats = {0};
protocol_stats_t udp_stats = {0};
protocol_stats_t icmp_stats = {0};
protocol_stats_t ethernet_stats = {0};

void protocol_stats_init() {
    memset(&ip_stats, 0, sizeof(protocol_stats_t));
    memset(&tcp_stats, 0, sizeof(protocol_stats_t));
    memset(&udp_stats, 0, sizeof(protocol_stats_t));
    memset(&icmp_stats, 0, sizeof(protocol_stats_t));
    memset(&ethernet_stats, 0, sizeof(protocol_stats_t));
}

protocol_stats_t get_ip_stats() {
    return ip_stats;
}

protocol_stats_t get_tcp_stats() {
    return tcp_stats;
}

protocol_stats_t get_udp_stats() {
    return udp_stats;
}

protocol_stats_t get_icmp_stats() {
    return icmp_stats;
}

protocol_stats_t get_ethernet_stats() {
    return ethernet_stats;
}

int protocol_stats_to_json(char *buf, size_t buf_size) {
    // 使用 unsigned long long 转换，避免 PRIu64 宏在 snprintf 中无法展开的问题
    int len = snprintf(buf, buf_size,
        "{"
        "\"ip\":{"
        "\"packets_sent\":%llu,"
        "\"packets_received\":%llu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"errors\":%llu"
        "},"
        "\"tcp\":{"
        "\"packets_sent\":%llu,"
        "\"packets_received\":%llu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"errors\":%llu"
        "},"
        "\"udp\":{"
        "\"packets_sent\":%llu,"
        "\"packets_received\":%llu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"errors\":%llu"
        "},"
        "\"icmp\":{"
        "\"packets_sent\":%llu,"
        "\"packets_received\":%llu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"errors\":%llu"
        "},"
        "\"ethernet\":{"
        "\"packets_sent\":%llu,"
        "\"packets_received\":%llu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"errors\":%llu"
        "}"
        "}",
        (unsigned long long)ip_stats.packets_sent, (unsigned long long)ip_stats.packets_received, 
        (unsigned long long)ip_stats.bytes_sent, (unsigned long long)ip_stats.bytes_received, 
        (unsigned long long)ip_stats.errors,
        (unsigned long long)tcp_stats.packets_sent, (unsigned long long)tcp_stats.packets_received, 
        (unsigned long long)tcp_stats.bytes_sent, (unsigned long long)tcp_stats.bytes_received, 
        (unsigned long long)tcp_stats.errors,
        (unsigned long long)udp_stats.packets_sent, (unsigned long long)udp_stats.packets_received, 
        (unsigned long long)udp_stats.bytes_sent, (unsigned long long)udp_stats.bytes_received, 
        (unsigned long long)udp_stats.errors,
        (unsigned long long)icmp_stats.packets_sent, (unsigned long long)icmp_stats.packets_received, 
        (unsigned long long)icmp_stats.bytes_sent, (unsigned long long)icmp_stats.bytes_received, 
        (unsigned long long)icmp_stats.errors,
        (unsigned long long)ethernet_stats.packets_sent, (unsigned long long)ethernet_stats.packets_received, 
        (unsigned long long)ethernet_stats.bytes_sent, (unsigned long long)ethernet_stats.bytes_received, 
        (unsigned long long)ethernet_stats.errors
    );
    return len;
}
