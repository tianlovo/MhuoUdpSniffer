package com.tlovo.analyze.packet;

import com.tlovo.util.CryptoHelper;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.Data;

/**
 * Kcp通信协议结构类
 */
@Data
public class Kcp {
    public static final int MIN_LENGTH = 28;

    /** 会话ID */
    private long conv;

    /** KCP指令值 */
    private byte cmd;

    /** 当前分片序号 */
    private byte frg;

    /** 窗口大小 */
    private short wnd;

    /** 该数据发送时的时间戳 */
    private int ts;

    /** 包序号 **/
    private int sn;

    /** 下个期望包序号 */
    private int una;

    /** 该Kcp数据包携带的负载数据长度 */
    private int len;

    /** 该Kcp数据包携带的负载数据 */
    private ProtoPacket protoPacket;

    /** 该Kcp数据包携带的负载字节数据 */
    private byte[] payload;

    /**
     * 从字节数组解析KCP协议数据包
     * @param payload UDP协议数据包的KCP字节数组
     * @param xorKey 解密KCP负载数据的xor异或密钥
     * @return 解析的KCP协议数据包
     */
    public static Kcp parse(byte[] payload, byte[] xorKey) {
        if (payload.length < MIN_LENGTH) return null;
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(payload);

        Kcp kcp = new Kcp();
        kcp.setConv(buffer.readLong());
        kcp.setCmd(buffer.readByte());
        kcp.setFrg(buffer.readByte());
        kcp.setWnd(buffer.readShortLE());
        kcp.setTs(buffer.readInt());
        kcp.setSn(buffer.readIntLE());
        kcp.setUna(buffer.readIntLE());
        kcp.setLen(buffer.readIntLE());

        byte[] data = new byte[kcp.getLen()];
        buffer.readBytes(data);

        kcp.setPayload(data);

        if (xorKey != null) {
            CryptoHelper.xorDecrypt(data, xorKey);
        }
        kcp.setProtoPacket(ProtoPacket.parse(data));

        buffer.release();
        return kcp;
    }
}
