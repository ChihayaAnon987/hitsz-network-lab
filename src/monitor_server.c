#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "protocol_stats.h"

#pragma comment(lib, "ws2_32.lib")

#define MONITOR_PORT 9999
#define MAX_CLIENTS 10

typedef struct {
    SOCKET sock;
    int active;
} client_t;

static client_t clients[MAX_CLIENTS];
static CRITICAL_SECTION clients_lock;

/**
 * @brief 广播统计数据给所有连接的客户端
 */
void broadcast_stats() {
    char buffer[8192];
    int len = protocol_stats_to_json(buffer, sizeof(buffer) - 2);
    if (len > 0) {
        buffer[len++] = '\n';  // 添加换行符作为消息边界
        buffer[len] = '\0';
    }
    
    EnterCriticalSection(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].sock != INVALID_SOCKET) {
            send(clients[i].sock, buffer, len, 0);
        }
    }
    LeaveCriticalSection(&clients_lock);
}

/**
 * @brief 客户端处理线程
 */
DWORD WINAPI client_handler(LPVOID arg) {
    int client_id = (intptr_t)arg;
    SOCKET client_sock = clients[client_id].sock;
    char buffer[1024];
    
    while (clients[client_id].active) {
        int recv_len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (recv_len <= 0) {
            break;
        }
        
        buffer[recv_len] = '\0';
        
        // 处理客户端请求
        if (strstr(buffer, "GET_STATS") != NULL) {
            char stats_buffer[8192];
            int len = protocol_stats_to_json(stats_buffer, sizeof(stats_buffer) - 2);
            if (len > 0) {
                stats_buffer[len++] = '\n';  // 添加换行符作为消息边界
                stats_buffer[len] = '\0';
            }
            send(client_sock, stats_buffer, len, 0);
        }
    }
    
    closesocket(client_sock);
    EnterCriticalSection(&clients_lock);
    clients[client_id].active = 0;
    clients[client_id].sock = INVALID_SOCKET;
    LeaveCriticalSection(&clients_lock);
    
    return 0;
}

/**
 * @brief 监控服务器主线程
 */
DWORD WINAPI monitor_server_thread(LPVOID arg) {
    SOCKET listen_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    
    // 创建socket
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        printf("Failed to create socket\n");
        return 1;
    }
    
    // 允许地址重用
    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
        printf("setsockopt failed\n");
        closesocket(listen_sock);
        return 1;
    }
    
    // 绑定
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(MONITOR_PORT);
    
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return 1;
    }
    
    // 监听
    if (listen(listen_sock, MAX_CLIENTS) < 0) {
        printf("Listen failed\n");
        closesocket(listen_sock);
        return 1;
    }
    
    printf("Monitor server listening on port %d\n", MONITOR_PORT);
    
    // 接受客户端连接
    while (1) {
        SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        // 查找空闲的客户端槽位
        EnterCriticalSection(&clients_lock);
        int client_id = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) {
                client_id = i;
                clients[i].sock = client_sock;
                clients[i].active = 1;
                break;
            }
        }
        LeaveCriticalSection(&clients_lock);
        
        if (client_id >= 0) {
            printf("Client %d connected\n", client_id);
            HANDLE thread = CreateThread(NULL, 0, client_handler, (LPVOID)(intptr_t)client_id, 0, NULL);
            if (thread == NULL) {
                closesocket(client_sock);
                EnterCriticalSection(&clients_lock);
                clients[client_id].active = 0;
                LeaveCriticalSection(&clients_lock);
            } else {
                CloseHandle(thread);
            }
        } else {
            closesocket(client_sock);
            printf("Too many clients, rejecting connection\n");
        }
    }
    
    closesocket(listen_sock);
    return 0;
}

/**
 * @brief 初始化监控服务器
 */
void monitor_server_init() {
    // 初始化Winsock
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }
    
    // 初始化客户端数组
    memset(clients, 0, sizeof(clients));
    InitializeCriticalSection(&clients_lock);
    
    // 创建服务器线程
    HANDLE thread = CreateThread(NULL, 0, monitor_server_thread, NULL, 0, NULL);
    if (thread == NULL) {
        printf("Failed to create monitor server thread\n");
        WSACleanup();
        return;
    }
    CloseHandle(thread);
}

/**
 * @brief 清理监控服务器
 */
void monitor_server_cleanup() {
    EnterCriticalSection(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].sock != INVALID_SOCKET) {
            closesocket(clients[i].sock);
        }
    }
    LeaveCriticalSection(&clients_lock);
    DeleteCriticalSection(&clients_lock);
    WSACleanup();
}
