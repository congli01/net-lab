#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
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
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    // 对txbuf进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // ARP报文
    arp_pkt_t *data = (arp_pkt_t *)txbuf.data;
    memcpy(data, &arp_init_pkt, sizeof(arp_pkt_t));

    // 操作类型为ARP_REQUEST
    data->opcode16 = swap16(ARP_REQUEST);

    // 接收方协议地址
    memcpy(data->target_ip, target_ip, NET_IP_LEN);

    // 广播发送ARP报文
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    // 初始化txbuf
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写ARP报头首部
    arp_pkt_t *data = (arp_pkt_t *)txbuf.data;
    memcpy(data, &arp_init_pkt, sizeof(arp_pkt_t));
    // 操作类型
    data->opcode16 = swap16(ARP_REPLY);
    // 接收方协议地址
    memcpy(data->target_ip, target_ip, NET_IP_LEN);
    // 接收方MAC地址
    memcpy(data->target_mac, target_mac, NET_MAC_LEN);

    // 发送ARP报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < sizeof(arp_pkt_t))
    {
        // 数据包不完整，丢弃不处理
        return;     
    }

    // 报头检查
    arp_pkt_t *data = (arp_pkt_t *) buf->data;
    if (data->hw_type16 != swap16(ARP_HW_ETHER) ||
        data->pro_type16 != swap16(NET_PROTOCOL_IP) || 
        data->hw_len != NET_MAC_LEN || 
        data->pro_len != NET_IP_LEN || 
        (data->opcode16 != swap16(ARP_REPLY) && data->opcode16 != swap16(ARP_REQUEST))
        ) return;

    // 更新ARP表项
    map_set(&arp_table, data->sender_ip, src_mac);

    // 检查该接收报文的IP地址是否有对应的arp缓存
    // 若有将其发送并从缓存中删除
    buf_t *old_buf = map_get(&arp_buf, data->sender_ip);
    if (old_buf != NULL)
    {
        ethernet_out(old_buf, src_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, data->sender_ip);
        return;
    }

    // 判断是否为请求报文，且报文的target_ip为本机IP
    if (data->opcode16 == swap16(ARP_REQUEST) && 
        memcmp(data->target_ip, net_if_ip, NET_IP_LEN) == 0)
    {
        arp_resp(data->sender_ip, data->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // 查ARP表
    uint8_t *mac = map_get(&arp_table, ip);
    // 找到MAC地址
    if (mac != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }

    // 未找到对应MAC地址，判断arp缓存是否被占用
    if (map_get(&arp_buf, ip) == NULL)
    {
        // 缓存区没有当前IP地址对应的数据包，将当前数据包缓存，并发送arp请求
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }


}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}