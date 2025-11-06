#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // 初始化缓冲区并填充ARP请求报文
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 设置为目标请求并填入目标IP
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // 发送ARP请求
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // 初始化缓冲区并填充ARP响应报文
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // 设置为ARP响应并填入目标IP和MAC
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);

    // 发送ARP响应
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // 检查数据包长度是否有效
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }

    // 检查ARP报头是否符合协议规范
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    if (arp_pkt->hw_type16 != swap16(ARP_HW_ETHER))
        return;
    if (arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP))
        return;
    if (arp_pkt->hw_len != NET_MAC_LEN)
        return;
    if (arp_pkt->pro_len != NET_IP_LEN)
        return;
    if (arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY))
        return;

    // 更新ARP表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    // 检查是否有对应的缓冲数据包需要发送
    buf_t *buf2 = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
    if (buf2 != NULL) {
        // 有缓存的数据包，将其发送并删除缓存
        ethernet_out(buf2, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 没有缓存数据包，检查是否需要响应ARP请求
        if (arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            // 回应ARP请求
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // 查找目标IP对应的MAC地址
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);

    if (mac != NULL) {
        // 找到MAC地址，直接发送数据包
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // 未找到MAC地址，检查是否已有ARP请求在等待
        buf_t *buf2 = (buf_t *)map_get(&arp_buf, ip);
        if (buf2 != NULL) {
            // 已有请求在等待，无需重复发送
            return;
        } else {
            // 如果没有，则将来自 IP 层的数据包缓存到 arp_buf，发送一个请求与目标 IP 地址对应的 MAC 地址的 ARP 请求报文
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}