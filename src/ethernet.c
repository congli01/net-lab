#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    // 判断数据长度，若小于以太网头部长度，则认为数据包不完整，丢弃
    if (buf->len < sizeof(ether_hdr_t))
    {
        fprintf(stderr, "Error in ethernet_in\n");
        return;
    }

    // 移除以太网包头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));

    // 向上层传递数据包
    net_in(buf, swap16(hdr->protocol16), hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    // 有效数据小于以太网最小传输单元长度，则填充
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) 
    {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    // 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    // 目的MAC地址
    memcpy(hdr->dst, mac, NET_MAC_LEN * sizeof(uint8_t));
    // 源MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN * sizeof(uint8_t));
    // 协议类型
    hdr->protocol16 = swap16(protocol);
    // 将数据帧发送到驱动层
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
