/*
 * Author : Juicer
 * BALABALA
 */
#ifndef __llc_decap_H__
#define __llc_decap_H__

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>


//控制帧帧头
struct ctr_hdr
{
	u16 d_or_c:1,  //数据还是控制, 1表示控制
		ctl_frame_t:4,//控制帧类型
		res1:3,//保留
		vehicle_id:8;//移动应急车ID
	u16 len:8,//控制字段长度，不包括控制头部4字节长度
		res2:8; //保留
};

//数据帧帧头
struct data_hdr
{
	u16 d_or_c:1, //数据还是控制, 1表示控制
		ack_flag:1,// 是否捎带ARQ ACK,如果捎带，则置1，ARQ ACK捎带在数据之后
		frag_flag:2,//分片标志
		llc_id:3,//业务流ID
		res1:1,//保留
		vehicle_id:8; //移动应急车ID
	u16 frag_sn:8,//分片序号
		re_frag_num:4,//再分割包数
		re_frag_sn:4;//再分割序号
	u32 pkt_sn:12,//数据包序号
		len:14,//数据包长度，不包括包头struct data_hdr
		res3:6; //保留
};



int vehicle_udp_decap(struct sk_buff *skb);	// Decapsulate IP&UDP head.
struct sk_buff * vehicle_llc_decap_zerocpoy(struct sk_buff *skb);
struct sk_buff * vehicle_llc_decap_datacopy(struct sk_buff *skb);


#endif
