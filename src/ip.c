#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include "protocol_stats.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t))
        return;

    // 创建备份用于可能的ICMP不可达消息
    buf_t copy;
    buf_copy(&copy, buf, buf->len);

    // 检查IP版本和长度字段
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    if (hdr->version != IP_VERSION_4)
        return;
    if (swap16(hdr->total_len16) > buf->len)
        return;

    // 验证头部校验和
    uint16_t hdr_checksum16_backup = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    if (hdr_checksum16 != hdr_checksum16_backup)
        return;
    hdr->hdr_checksum16 = hdr_checksum16_backup;

    // 检查目标IP地址
    uint8_t loopback_ip[4] = {127, 0, 0, 1};
    int is_our_packet = (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) == 0) || 
                        (memcmp(hdr->dst_ip, loopback_ip, NET_IP_LEN) == 0);
    
    if (!is_our_packet) {
        return;
    }

    // 移除填充字段
    if (buf->len > swap16(hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));

    // 提取协议、源IP和TTL，然后移除IP头部
    uint8_t protocol = hdr->protocol;
    uint8_t *src_ip = hdr->src_ip;
    uint8_t ttl = hdr->ttl;
    uint16_t total_len = swap16(hdr->total_len16);
    buf_remove_header(buf, hdr->hdr_len * 4);

    // 移除IP头后再设置TTL
    if (protocol == NET_PROTOCOL_ICMP) {
#ifdef PING  // 仅在PING测试模式下修改TTL，避免其他模块（如ip_test）因缺少icmp相关函数而报错
        set_ping_req_TTL(ttl, buf);
#endif
    }

    // 更新统计数据
    ip_stats.packets_received++;
    ip_stats.bytes_received += total_len;

    // 向上层传递数据包
    int flag = net_in(buf, protocol, src_ip);
    if (flag == -1)
        icmp_unreachable(&copy, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // 添加IP头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    // 填充IP头部字段
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    // 计算并填充头部校验和
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));

    // 更新统计数据
    ip_stats.packets_sent++;
    ip_stats.bytes_sent += buf->len;

    // 发送数据包
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // 检查是否是回环地址
    uint8_t loopback_ip[4] = {127, 0, 0, 1};
    if (memcmp(ip, loopback_ip, NET_IP_LEN) == 0) {
        // 对于回环地址，直接将数据包传回本机
        buf_add_header(buf, sizeof(ip_hdr_t));
        ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
        hdr->version = IP_VERSION_4;
        hdr->hdr_len = sizeof(ip_hdr_t) / 4;
        hdr->tos = 0;
        hdr->total_len16 = swap16(buf->len);
        hdr->id16 = 0;
        hdr->flags_fragment16 = 0;
        hdr->ttl = 64;
        hdr->protocol = protocol;
        memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
        memcpy(hdr->dst_ip, ip, NET_IP_LEN);
        
        // 计算并填充头部校验和
        hdr->hdr_checksum16 = 0;
        hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
        
        // 直接调用ip_in处理
        ip_in(buf, NULL);
        return;
    }
    
    // 计算IP最大负载长度(MTU减去IP头部长度)
    int max_load_length = 1500 - sizeof(ip_hdr_t);

    // 分片发送数据包
    int i;
    static int id = 0;
    for (i = 0; (i + 1) * max_load_length < buf->len; i++) {
        buf_t ip_buf;
        buf_init(&ip_buf, max_load_length);
        memcpy(ip_buf.data, buf->data + i * max_load_length, max_load_length);
        ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_length >> 3), 1);
    }

    // 发送最后一个分片，设置MF为0
    buf_t ip_buf;
    buf_init(&ip_buf, buf->len - i * max_load_length);
    memcpy(ip_buf.data, buf->data + i * max_load_length, buf->len - i * max_load_length);
    ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_length >> 3), 0);

    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}