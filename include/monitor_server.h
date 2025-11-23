#ifndef MONITOR_SERVER_H
#define MONITOR_SERVER_H

/**
 * @brief 初始化监控服务器
 * 在协议栈初始化时调用，启动TCP监控服务器
 */
void monitor_server_init();

/**
 * @brief 清理监控服务器
 * 在协议栈关闭时调用，清理监控服务器资源
 */
void monitor_server_cleanup();

#endif // MONITOR_SERVER_H
