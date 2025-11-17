#include "driver.h"
#include "net.h"
#include "icmp.h"

int main(int argc, char const *argv[]) {
    if (net_init() == -1) {  
        printf("net init failed.");
        return -1;
    }

    int test_time = 2;
    uint8_t to_ping_ip[2][NET_IP_LEN] = {{169, 254, 176, 237},{127, 0, 0, 1}};
    char* descibe[] = {"同一子网ip", "回环地址"};

    for (int i = 0; i < test_time; i++) {
        printf("---------------------------------------------------------------\n");
        printf("下面测试ping%s:\n", descibe[i]);
        while (1) {
            if (ping_req(to_ping_ip[i])) {
                break;
            }
            net_poll();
        }
    }
    printf("测试结束。\n");

    while (1) {
        net_poll(); 
    }
    
    return 0;
}