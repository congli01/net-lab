#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

int ip_id = 0;     // 数据包id

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 如果数据包的长度小于IP头部长度，丢弃不处理
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }

    // 报头检测
    ip_hdr_t *ip_hdr = (ip_hdr_t *) buf->data;
    if (ip_hdr->version != IP_VERSION_4 ||
        swap16(ip_hdr->total_len16) > buf->len) return;

    // 检查首部校验和
    uint16_t hcs16 = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    // 如果计算出的首部校验和与原来不一致，则丢弃；若一致则恢复头部的校验和字段
    uint16_t hcs16_new = checksum16((uint16_t *)ip_hdr, IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len);
    if (hcs16 != hcs16_new) 
    {
        return;
    }
    else
    {
        ip_hdr->hdr_checksum16 = hcs16;
    }

    // 对比目的IP地址是否为本机IP地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;

    // 去除填充字段
    if (buf->len > swap16(ip_hdr->total_len16))
    {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    // 检查上层协议类型
    if (ip_hdr->protocol != NET_PROTOCOL_ICMP && ip_hdr->protocol != NET_PROTOCOL_UDP)
    {
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }

    // 去掉IP报头
    buf_remove_header(buf, sizeof(ip_hdr_t));

    // 向上层传递数据包
    net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);

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
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    // 填写IP数据报头部字段
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0; 
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = mf ? swap16(IP_MORE_FRAGMENT | offset) : swap16(offset);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);

    // 发送
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO

    // 检查数据包长是否大于MTU
    // 若数据包长不大于MTU，直接发送
    uint32_t max_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);  // IP协议最大负载包长
    if (buf->len <= max_len)
    {
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
        ip_id ++;
        return;
    }

    // 数据包长度大于MTU，需要分片发送
    buf_t IP_BUF;
    buf_t *ip_buf = &IP_BUF;
    uint32_t total = 0;     // 已经发送的数据长度
    while (buf->len > max_len)
    {
        buf_init(ip_buf, max_len);
        memcpy(ip_buf->data, buf->data, max_len);
        buf_remove_header(buf, max_len);
        ip_fragment_out(ip_buf, ip, protocol, ip_id, total / IP_HDR_OFFSET_PER_BYTE, 1);
        total += max_len;
    }

    // 最后一个分片
    buf_init(ip_buf, buf->len);
    memcpy(ip_buf->data, buf->data, buf->len);
    ip_fragment_out(ip_buf, ip, protocol, ip_id, total / IP_HDR_OFFSET_PER_BYTE, 0);
    ip_id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}