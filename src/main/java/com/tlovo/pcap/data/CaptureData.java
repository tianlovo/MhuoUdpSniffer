package com.tlovo.pcap.data;

import com.alibaba.fastjson2.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

/**
 * 捕获数据保存数据结构类
 */
@NoArgsConstructor
@AllArgsConstructor
public class CaptureData {

    /**
     * 数据包源端口
     */
    @JSONField(name = "source_port")
    public short SrcPort;

    /**
     * 数据包目标端口
     */
    @JSONField(name = "dst_port")
    public short DstPort;

    /**
     * 接收该数据包时的时间戳(ms)
     */
    @JSONField(name = "ts")
    public long RecvTs;

    /**
     * Udp完整数据Base64字符串
     * <br/>
     * 包含UDP头部+KCP头部+Xor加密数据
     */
    @JSONField(name = "udp_data")
    public String UdpData;
}
