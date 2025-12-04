#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include "protocol_stats.h"

#include <time.h>

/**
 * @brief IP分片重组所用的片段结构体
 * 记录单个分片的信息
 */
typedef struct ip_fragment {
    uint16_t offset;        // 分片偏移（字节单位）
    uint16_t len;           // 分片数据长度
    uint8_t *data;          // 分片数据缓冲区
    uint8_t is_last;        // 该片是否为最后一片（MF=0）
} ip_fragment_t;

/**
 * @brief IP包重组所用的信息结构体
 * 用于管理同一个IP包的多个分片
 */
typedef struct ip_reassemble_node {
    uint8_t src_ip[NET_IP_LEN];           // 源IP地址
    uint8_t dst_ip[NET_IP_LEN];           // 目标IP地址
    uint16_t id;                          // IP包标识符
    uint8_t protocol;                     // 上层协议
    time_t arrival_time;                  // 分片首次到达的时间
    uint16_t total_len;                   // 重组后的总长度（在收到最后一片时确定）
    uint8_t has_last_fragment;            // 是否已收到最后一片（MF=0）
    uint16_t fragment_count;              // 当前已收到的分片数
    ip_fragment_t fragments[IP_FRAG_MAX_FRAGMENTS];  // 分片数组
} ip_reassemble_node_t;

/**
 * @brief IP重组缓冲区
 * 用map容器管理所有重组中的IP包
 */
static map_t ip_reassemble_map;

/**
 * @brief 比较两个IP包是否相同（通过源IP、目标IP、ID）
 * 用作map的key比较函数
 */
static int ip_reassemble_key_compare(const void *a, const void *b, size_t n) {
    return memcmp(a, b, n);
}

/**
 * @brief IP包重组Key结构体
 */
typedef struct {
    uint8_t src_ip[NET_IP_LEN];
    uint8_t dst_ip[NET_IP_LEN];
    uint16_t id;
} ip_reassemble_key_t;

/**
 * @brief 初始化IP重组
 */
static void ip_reassemble_init() {
    static int initialized = 0;
    if (!initialized) {
        initialized = 1;
        map_init(&ip_reassemble_map, sizeof(ip_reassemble_key_t), 
                 sizeof(ip_reassemble_node_t), 0, IP_FRAG_TIMEOUT_SEC, 
                 ip_reassemble_key_compare, NULL);
    }
}

/**
 * @brief 检查IP包是否重组完成
 * 
 * @param node 重组节点
 * @return 1 表示完成，0 表示未完成
 */
static int ip_reassemble_is_complete(ip_reassemble_node_t *node) {
    if (!node->has_last_fragment)
        return 0;  // 还没有收到最后的分片
    
    // 检查是否所有分片都已到达
    uint16_t expected_offset = 0;
    for (uint16_t i = 0; i < node->fragment_count; i++) {
        if (node->fragments[i].offset != expected_offset)
            return 0;  // 分片存在间隙
        expected_offset += node->fragments[i].len;
    }
    
    return expected_offset == node->total_len;
}

/**
 * @brief 将多个分片合并成完整的IP负载
 * 
 * @param node 重组节点
 * @param output_buf 输出缓冲区
 * @return 合并后的数据长度
 */
static uint16_t ip_reassemble_merge_fragments(ip_reassemble_node_t *node, uint8_t *output_buf) {
    uint16_t offset = 0;
    for (uint16_t i = 0; i < node->fragment_count; i++) {
        memcpy(output_buf + offset, node->fragments[i].data, node->fragments[i].len);
        offset += node->fragments[i].len;
    }
    return offset;
}

/**
 * @brief 获取或创建IP重组节点
 * 
 * @param src_ip 源IP
 * @param dst_ip 目标IP
 * @param id IP包标识符
 * @return 重组节点指针
 */
static ip_reassemble_node_t *ip_reassemble_get_node(uint8_t *src_ip, uint8_t *dst_ip, uint16_t id) {
    ip_reassemble_key_t key;
    memcpy(key.src_ip, src_ip, NET_IP_LEN);
    memcpy(key.dst_ip, dst_ip, NET_IP_LEN);
    key.id = id;
    
    ip_reassemble_node_t *node = (ip_reassemble_node_t *)map_get(&ip_reassemble_map, &key);
    
    if (node == NULL) {
        // 创建新节点
        ip_reassemble_node_t new_node;
        memset(&new_node, 0, sizeof(ip_reassemble_node_t));
        memcpy(new_node.src_ip, src_ip, NET_IP_LEN);
        memcpy(new_node.dst_ip, dst_ip, NET_IP_LEN);
        new_node.id = id;
        new_node.arrival_time = time(NULL);
        map_set(&ip_reassemble_map, &key, &new_node);
        node = (ip_reassemble_node_t *)map_get(&ip_reassemble_map, &key);
    } else {
        // 更新到达时间
        node->arrival_time = time(NULL);
    }
    
    return node;
}

/**
 * @brief 在重组节点中插入一个分片
 * 支持乱序插入，会自动维护分片的排序
 * 
 * @param node 重组节点
 * @param offset 分片偏移
 * @param len 分片长度
 * @param data 分片数据
 * @param is_last 是否为最后一片
 * @return 1 成功，0 失败（分片重复或超出限制）
 */
static int ip_reassemble_insert_fragment(ip_reassemble_node_t *node, uint16_t offset, 
                                         uint16_t len, uint8_t *data, uint8_t is_last) {
    // 检查分片数量是否超限
    if (node->fragment_count >= IP_FRAG_MAX_FRAGMENTS)
        return 0;
    
    // 分配数据缓冲区
    uint8_t *frag_data = (uint8_t *)malloc(len);
    if (frag_data == NULL)
        return 0;
    
    memcpy(frag_data, data, len);
    
    // 找到合适的插入位置（保持offset递增）
    int insert_pos = node->fragment_count;
    for (int i = 0; i < node->fragment_count; i++) {
        // 检查分片是否重复
        if (node->fragments[i].offset == offset && node->fragments[i].len == len) {
            free(frag_data);
            return 0;  // 分片已存在
        }
        
        if (node->fragments[i].offset > offset) {
            insert_pos = i;
            break;
        }
    }
    
    // 将分片向后移动以腾出空间
    if (insert_pos < node->fragment_count) {
        memmove(&node->fragments[insert_pos + 1], &node->fragments[insert_pos],
                (node->fragment_count - insert_pos) * sizeof(ip_fragment_t));
    }
    
    // 插入新分片
    node->fragments[insert_pos].offset = offset;
    node->fragments[insert_pos].len = len;
    node->fragments[insert_pos].data = frag_data;
    node->fragments[insert_pos].is_last = is_last;
    node->fragment_count++;
    
    // 如果是最后一片，更新总长度
    if (is_last) {
        node->has_last_fragment = 1;
        node->total_len = offset + len;
    }
    
    return 1;
}

/**
 * @brief 清理IP重组节点（释放分片数据）
 * 
 * @param node 重组节点
 */
static void ip_reassemble_free_node(ip_reassemble_node_t *node) {
    for (uint16_t i = 0; i < node->fragment_count; i++) {
        if (node->fragments[i].data != NULL) {
            free(node->fragments[i].data);
            node->fragments[i].data = NULL;
        }
    }
    node->fragment_count = 0;
}

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

    // 提取协议、源IP、目标IP、TTL和总长度
    uint8_t protocol = hdr->protocol;
    uint8_t *src_ip = hdr->src_ip;
    uint8_t *dst_ip = hdr->dst_ip;
    uint8_t ttl = hdr->ttl;
    uint16_t total_len = swap16(hdr->total_len16);
    uint16_t id = swap16(hdr->id16);
    uint16_t flags_fragment = swap16(hdr->flags_fragment16);
    uint8_t mf = (flags_fragment & IP_MORE_FRAGMENT) != 0;
    uint16_t frag_offset = (flags_fragment & 0x1FFF) * IP_HDR_OFFSET_PER_BYTE;  // 转换为字节单位
    
    // 在非PING模式下标记ttl为已使用
#ifndef PING
    (void)ttl;
#endif
    
    // 移除IP头部
    buf_remove_header(buf, hdr->hdr_len * 4);
    uint16_t payload_len = buf->len;

    // 如果MF=0 且 offset=0，说明这是一个未分片的IP包，直接处理
    if (!mf && frag_offset == 0) {
        // 未分片的IP包
        if (protocol == NET_PROTOCOL_ICMP) {
#ifdef PING
            set_ping_req_TTL(ttl, buf);
#endif
        }
        
        ip_stats.packets_received++;
        ip_stats.bytes_received += total_len;
        
        int flag = net_in(buf, protocol, src_ip);
        if (flag == -1)
            icmp_unreachable(&copy, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }
    
    // 处理分片的IP包
    ip_reassemble_init();
    ip_reassemble_node_t *node = ip_reassemble_get_node(src_ip, dst_ip, id);
    
    if (node == NULL) {
        return;  // 内存不足
    }
    
    // 调试信息：记录接收到的分片
    printf("[IP重组] 接收分片     - ID:%4d, 偏移:%5d, 长度:%4d, MF:%d\n", 
           id, frag_offset, payload_len, mf);
    
    // 尝试插入分片
    if (!ip_reassemble_insert_fragment(node, frag_offset, payload_len, buf->data, !mf)) {
        printf("[IP重组] 分片插入失败 - ID:%4d, 偏移:%5d\n", id, frag_offset);
        return;  // 分片插入失败（可能是重复分片）
    }
    
    printf("[IP重组] 分片已插入   - ID:%4d, 当前分片数:%2d\n", id, node->fragment_count);
    
    // 检查是否重组完成
    if (ip_reassemble_is_complete(node)) {
        printf("[IP重组] 重组完成     - ID:%4d, 总长度:%5d\n", id, node->total_len);
        
        // 重组完成，创建完整的IP包缓冲区
        buf_t reassembled_buf;
        uint16_t reassembled_len = node->total_len;
        buf_init(&reassembled_buf, reassembled_len);
        
        // 合并所有分片
        ip_reassemble_merge_fragments(node, reassembled_buf.data);
        
        // 清理重组节点
        ip_reassemble_free_node(node);
        ip_reassemble_key_t key;
        memcpy(key.src_ip, src_ip, NET_IP_LEN);
        memcpy(key.dst_ip, dst_ip, NET_IP_LEN);
        key.id = id;
        map_delete(&ip_reassemble_map, &key);
        
        // 处理重组后的IP包
        if (protocol == NET_PROTOCOL_ICMP) {
#ifdef PING
            set_ping_req_TTL(ttl, &reassembled_buf);
#endif
        }
        
        ip_stats.packets_received++;
        ip_stats.bytes_received += reassembled_len;
        
        int flag = net_in(&reassembled_buf, protocol, src_ip);
        if (flag == -1)
            icmp_unreachable(&copy, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    } else {
        printf("[IP重组] 等待更多分片 - ID:%4d, 已收%2d片, 待最后片:%s\n", 
               id, node->fragment_count, node->has_last_fragment ? "是" : "否");
    }
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
    ip_reassemble_init();
}