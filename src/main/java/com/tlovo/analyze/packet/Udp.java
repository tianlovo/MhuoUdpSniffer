package com.tlovo.analyze.packet;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.Data;
import org.pcap4j.packet.UdpPacket;

/**
 * UDP通信协议结构类
 */
@Data
public class Udp {
    public static final int MIN_LENGTH = 8;

    /** 源端口号 */
    private short srcPort;

    /** 目标端口号 */
    private short dstPort;

    /** 整个UDP数据包的长度 */
    private short len;

    /** 校验和 */
    private short checkSum;

    /** 负载KCP数据 */
    private Kcp kcp;

    /** 负载字节数据 */
    private byte[] payload;

    /**
     * 从字节数组解析UDP协议数据包
     * @param payload UDP协议数据包的字节数组
     * @param xorKey 解密KCP负载数据的xor异或密钥
     * @return 解析的UDP协议数据包
     */
    public static Udp parse(byte[] payload, byte[] xorKey) {
        if (payload.length < MIN_LENGTH) return null;
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(payload);

        Udp udp = new Udp();
        udp.setSrcPort(buffer.readShort());
        udp.setDstPort(buffer.readShort());
        udp.setLen(buffer.readShort());
        udp.setCheckSum(buffer.readShort());

        byte[] data = new byte[udp.getLen() - MIN_LENGTH];
        buffer.readBytes(data);
        udp.setKcp(Kcp.parse(data, xorKey));

        if (udp.getKcp() == null) {
            udp.setPayload(data);
        }

        buffer.release();
        return udp;
    }

    /**
     * 从字节数组解析UDP协议数据包
     * @param packet UDP协议数据包
     * @param xorKey 解密KCP负载数据的xor异或密钥
     * @return 解析的UDP协议数据包
     */
    public static Udp parse(UdpPacket packet, byte[] xorKey) {
        Udp udp = new Udp();
        UdpPacket.UdpHeader header = packet.getHeader();
        udp.setSrcPort((short) header.getSrcPort().valueAsInt());
        udp.setDstPort((short) header.getDstPort().valueAsInt());
        udp.setLen(header.getLength());
        udp.setCheckSum(header.getChecksum());

        byte[] payload = packet.getPayload().getRawData();
        udp.setKcp(Kcp.parse(payload, xorKey));

        udp.setPayload(payload);

        return udp;
    }
}
