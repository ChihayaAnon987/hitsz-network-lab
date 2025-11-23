#ifndef PROTOCOL_STATS_H
#define PROTOCOL_STATS_H

#include <stdint.h>
#include <string.h>

/**
 * @brief 协议栈统计数据结构
 */
typedef struct {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t errors;
} protocol_stats_t;

/**
 * @brief TCP连接信息结构
 */
typedef struct {
    uint8_t remote_ip[4];
    uint16_t remote_port;
    uint16_t local_port;
    int state;
} tcp_connection_info_t;

/**
 * @brief 全局统计数据
 */
extern protocol_stats_t ip_stats;
extern protocol_stats_t tcp_stats;
extern protocol_stats_t udp_stats;
extern protocol_stats_t icmp_stats;
extern protocol_stats_t ethernet_stats;

/**
 * @brief 初始化统计数据
 */
void protocol_stats_init();

/**
 * @brief 获取IP层统计数据
 */
protocol_stats_t get_ip_stats();

/**
 * @brief 获取TCP层统计数据
 */
protocol_stats_t get_tcp_stats();

/**
 * @brief 获取UDP层统计数据
 */
protocol_stats_t get_udp_stats();

/**
 * @brief 获取ICMP层统计数据
 */
protocol_stats_t get_icmp_stats();

/**
 * @brief 获取以太网层统计数据
 */
protocol_stats_t get_ethernet_stats();

/**
 * @brief 生成JSON格式的统计数据
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 实际写入的字符数
 */
int protocol_stats_to_json(char *buf, size_t buf_size);

#endif // PROTOCOL_STATS_H
