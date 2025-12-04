#include "driver.h"
#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "icmp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

/**
 * IP重组测试程序
 * 
 * 直接构造IP分片报文并调用ip_in()进行测试，验证IP重组功能
 */

#define TEST_PROTOCOL 253
#define LOOPBACK_IP {127, 0, 0, 1}

// 统计信息
static int fragments_received = 0;

/**
 * @brief 创建一个IP分片报文并传递给ip_in处理
 * 
 * 注意：ip_in()期望buf中的数据是以太网帧格式
 * 结构: [以太网头(14字节)][IP头(20字节)][数据]
 */
static void send_fragment(uint8_t *src_ip, uint8_t *dst_ip, uint16_t id, 
                          uint16_t offset, uint8_t *data, uint16_t data_len, 
                          int mf) {
    // 创建完整的以太网帧
    buf_t frag_buf;
    uint16_t ip_packet_len = sizeof(ip_hdr_t) + data_len;
    uint16_t total_len = sizeof(ether_hdr_t) + ip_packet_len;
    buf_init(&frag_buf, total_len);
    
    // 设置以太网头（buf->data开始）
    ether_hdr_t *eth_hdr = (ether_hdr_t *)frag_buf.data;
    memset(eth_hdr->dst, 0xFF, NET_MAC_LEN);
    memcpy(eth_hdr->src, net_if_mac, NET_MAC_LEN);
    eth_hdr->protocol16 = swap16(NET_PROTOCOL_IP);
    
    // 设置IP头（在以太网头之后）
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(frag_buf.data + sizeof(ether_hdr_t));
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(ip_packet_len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset / 8));
    ip_hdr->ttl = 64;
    ip_hdr->protocol = TEST_PROTOCOL;
    memcpy(ip_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, dst_ip, NET_IP_LEN);
    
    // 计算IP头校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    
    // 复制数据到IP负载位置
    memcpy((uint8_t *)ip_hdr + sizeof(ip_hdr_t), data, data_len);
    
    frag_buf.len = total_len;
    
    // 记录分片
    fragments_received++;
    printf("  [分片 %2d]           ID:%4d | 偏移:%5d | 长度:%4d | MF:%d\n",
           fragments_received, id, offset, data_len, mf);
    
    // 调用ethernet_in处理以太网帧，它会调用ip_in进行重组
    ethernet_in(&frag_buf);
}

/**
 * @brief 测试场景1: 乱序分片
 */
static void test_out_of_order_fragments(void) {
    printf("\n========== 测试1: 乱序分片 ==================\n");
    printf("包大小: 2000字节  分片数: 2                    \n");
    printf("分片1: 偏移0    长度1480  MF=1                 \n");
    printf("分片2: 偏移1480 长度520   MF=0                 \n");
    printf("到达顺序: 分片2 → 分片1 (乱序)                  \n");
    printf("==============================================\n");
    
    uint8_t loopback_ip[4] = LOOPBACK_IP;
    uint8_t test_data1[1480];
    uint8_t test_data2[520];
    memset(test_data1, 0xAA, sizeof(test_data1));
    memset(test_data2, 0xBB, sizeof(test_data2));
    
    // 先发送第2片（偏移1480）
    send_fragment(loopback_ip, net_if_ip, 1001, 1480, test_data2, sizeof(test_data2), 0);
    
    // 再发送第1片（偏移0）
    send_fragment(loopback_ip, net_if_ip, 1001, 0, test_data1, sizeof(test_data1), 1);
}

/**
 * @brief 测试场景2: 多个包的分片交错
 */
static void test_interleaved_fragments(void) {
    printf("\n========== 测试2: 多包分片交错 ===============\n");
    printf("包A(1800字节): [偏移0:1480] [偏移1480:320]  \n");
    printf("包B(2200字节): [偏移0:1480] [偏移1480:720]  \n");
    printf("到达顺序: A1 → B1 → A2 → B2 (交错)         \n");
    printf("==============================================\n");
    
    uint8_t loopback_ip[4] = LOOPBACK_IP;
    uint8_t data_a1[1480], data_a2[320];
    uint8_t data_b1[1480], data_b2[720];
    memset(data_a1, 0xCC, sizeof(data_a1));
    memset(data_a2, 0xDD, sizeof(data_a2));
    memset(data_b1, 0xEE, sizeof(data_b1));
    memset(data_b2, 0xFF, sizeof(data_b2));
    
    // A1
    send_fragment(loopback_ip, net_if_ip, 1002, 0, data_a1, sizeof(data_a1), 1);
    // B1
    send_fragment(loopback_ip, net_if_ip, 1003, 0, data_b1, sizeof(data_b1), 1);
    // A2
    send_fragment(loopback_ip, net_if_ip, 1002, 1480, data_a2, sizeof(data_a2), 0);
    // B2
    send_fragment(loopback_ip, net_if_ip, 1003, 1480, data_b2, sizeof(data_b2), 0);
}

/**
 * @brief 测试场景3: 重复分片
 */
static void test_duplicate_fragments(void) {
    printf("\n========== 测试3: 重复分片处理 ===============\n");
    printf("包大小: 1780字节  分片数: 2                  \n");
    printf("分片1: 偏移0    长度1480  MF=1              \n");
    printf("分片1: 偏移0    长度1480  MF=1 (重复)       \n");
    printf("分片2: 偏移1480 长度300   MF=0              \n");
    printf("==============================================\n");
    
    uint8_t loopback_ip[4] = LOOPBACK_IP;
    uint8_t data[1480];
    memset(data, 0x11, sizeof(data));
    
    // 发送第1片
    send_fragment(loopback_ip, net_if_ip, 1004, 0, data, sizeof(data), 1);
    
    // 重复发送第1片（应被检测并丢弃）
    printf("  [重复]  同一分片重复到达，应被自动检测丢弃\n");
    send_fragment(loopback_ip, net_if_ip, 1004, 0, data, sizeof(data), 1);
    
    // 发送第2片完成重组
    uint8_t data2[300];
    memset(data2, 0x22, sizeof(data2));
    send_fragment(loopback_ip, net_if_ip, 1004, 1480, data2, sizeof(data2), 0);
}

/**
 * @brief 测试场景4: 不等长分片
 */
static void test_unequal_length_fragments(void) {
    printf("\n========== 测试4: 不等长分片处理 =============\n");
    printf("包大小: 3000字节  分片数: 3                  \n");
    printf("分片1: 偏移0    长度1200  MF=1               \n");
    printf("分片2: 偏移1200 长度800   MF=1               \n");
    printf("分片3: 偏移2000 长度1000  MF=0               \n");
    printf("到达顺序: 分片2 → 分片1 → 分片3 (乱序)        \n");
    printf("==============================================\n");
    
    uint8_t loopback_ip[4] = LOOPBACK_IP;
    uint8_t data1[1200], data2[800], data3[1000];
    memset(data1, 0x33, sizeof(data1));
    memset(data2, 0x44, sizeof(data2));
    memset(data3, 0x55, sizeof(data3));
    
    // 以乱序发送: 分片2 → 分片1 → 分片3
    send_fragment(loopback_ip, net_if_ip, 1005, 1200, data2, sizeof(data2), 1);
    send_fragment(loopback_ip, net_if_ip, 1005, 0, data1, sizeof(data1), 1);
    send_fragment(loopback_ip, net_if_ip, 1005, 2000, data3, sizeof(data3), 0);
}

/**
 * @brief 主函数
 */
int main(int argc, char const *argv[]) {
    system("chcp 65001 > nul");
    
    if (net_init() == -1) {
        fprintf(stderr, "[错误] 网络初始化失败\n");
        return -1;
    }
    
    printf("=========================================\n");
    printf("     IP分片重组功能测试程序               \n");
    printf("=========================================\n");
    
    // 执行各个测试场景
    test_out_of_order_fragments();
    
    Sleep(1000);
    test_interleaved_fragments();
    
    Sleep(1000);
    test_duplicate_fragments();
    
    Sleep(1000);
    test_unequal_length_fragments();
    
    printf("\n==============================================\n");
    printf("           测试完成统计                  \n");
    printf("==============================================\n");
    printf("[统计] 构造的分片总数: %d\n", fragments_received);
    printf("[统计] 预期重组成功的包数: 4\n");
    printf("[信息] 程序正常退出\n");
    
    return 0;
}