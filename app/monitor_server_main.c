#include <stdio.h>
#include <windows.h>
#include "../include/monitor_server.h"

/**
 * @brief main 函数 - 独立监控服务器
 */
int main() {
    monitor_server_init();
    // 运行服务器
    printf("Monitor server started. Press Ctrl+C to exit.\n");
    Sleep(INFINITE);
    monitor_server_cleanup();
    return 0;
}
