#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // 包检查
    if (buf->len < sizeof(udp_hdr_t))
        return;

    // 重新计算校验和
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    uint16_t checksum16_backup = hdr->checksum16;
    hdr->checksum16 = 0;
    uint16_t checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    if (checksum != checksum16_backup)
        return;
    hdr->checksum16 = checksum;

    // 查询处理函数
    uint16_t dst_port = swap16(hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);
    if (handler == NULL) {
        // 端口不可达
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, net_if_ip, ICMP_CODE_PORT_UNREACH);
    } else {
        // 找到, 调用处理程序
        buf_remove_header(buf, sizeof(ip_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(hdr->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // 添加UDP报头
    buf_add_header(buf, sizeof(udp_hdr_t));

    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);
    
    // 计算校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // 发送UDP数据包
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}