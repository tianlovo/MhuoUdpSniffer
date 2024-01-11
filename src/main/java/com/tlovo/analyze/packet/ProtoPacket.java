package com.tlovo.analyze.packet;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.Data;

/**
 * 协议包结构类
 */
@Data
public class ProtoPacket {
    public static final int MIN_LENGTH = 16;

    /** 头部魔数 */
    private int headMagic;

    /** 指令值 */
    private short cmdId;

    /** 头部长度 */
    private short headerLength;

    /** 数据长度 */
    private int dataLength;

    /** 头部数据 */
    private byte[] header;

    /** protobuf序列化字节数据 */
    private byte[] data;

    /** 尾部魔数 */
    private int tailMagic;

    /**
     * 从字节数组解析协议数据包
     * @param payload 协议数据包的字节数组
     * @return 解析的协议数据包
     */
    public static ProtoPacket parse(byte[] payload) {
        if (payload.length < MIN_LENGTH) return null;
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(payload);
        if (buffer.getInt(0) != PacketConst.HEADER_CONST) {
            buffer.release();
            return null;
        }
        if (buffer.getInt(buffer.readableBytes() - 4) != PacketConst.TAIL_CONST) {
            buffer.release();
            return null;
        }

        // 读取并创建ProtoPacket
        ProtoPacket packet = new ProtoPacket();
        packet.setHeadMagic(buffer.readInt());
        packet.setCmdId(buffer.readShort());
        packet.setHeaderLength(buffer.readShort());
        packet.setDataLength(buffer.readInt());

        byte[] header = new byte[packet.getHeaderLength()];
        buffer.readBytes(header);
        packet.setHeader(header);

        byte[] data = new byte[packet.getDataLength()];
        buffer.readBytes(data);
        packet.setData(data);

        packet.setTailMagic(buffer.readInt());

        buffer.release();
        return packet;
    }
}
