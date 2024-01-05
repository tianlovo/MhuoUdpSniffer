package com.tlovo.analyze;

import com.alibaba.fastjson2.JSON;
import com.google.protobuf.*;
import com.tlovo.MhuoUdpSniffer;
import com.tlovo.analyze.packet.PacketConst;
import com.tlovo.analyze.packet.ProtoField;
import com.tlovo.analyze.packet.ProtoMessage;
import com.tlovo.config.data.CaptureConfig;
import com.tlovo.config.data.KcpAnalyzeConfig;
import com.tlovo.config.data.LoggingConfig;
import com.tlovo.proto.EmptyMessageOuterClass.EmptyMessage;
import com.tlovo.util.BytesUtil;
import com.tlovo.util.CryptoHelper;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.extern.slf4j.Slf4j;

import java.io.FileDescriptor;
import java.util.Base64;
import java.util.List;

/**
 * Kcp数据分析器
 * <br/>
 * 将udp负载数据解析为KCP数据
 */
@Slf4j
public class KcpAnalyzer implements Runnable {
    /** 数据包发送者 */
    private final String sender;

    /** Udp负载数据 */
    private final byte[] udpPayload;

    /** KCP分析配置 */
    private final KcpAnalyzeConfig kcpAnalyzeConfig;
    /** 日志配置 */
    private final LoggingConfig loggingConfig;

    public KcpAnalyzer(String sender, byte[] udpPayload) {
        this.sender = sender;
        this.udpPayload = udpPayload;
        this.kcpAnalyzeConfig = MhuoUdpSniffer.getKcpAnalyzeConfig();
        this.loggingConfig = MhuoUdpSniffer.getLoggingConfig();
    }

    @Override
    public void run() {
        ByteBuf kcpBuf = decryptUdpPayload();
        if (kcpBuf != null) {
            byte[] proto = parseKcpPacket(kcpBuf);
            kcpBuf.release();

            ProtoMessage msg = parseUnknownProto(proto);
            // TODO 处理消息
        }
    }

    /**
     * 解密Udp负载
     */
    private ByteBuf decryptUdpPayload() {
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(udpPayload);

        // 根据魔数判断使用的xor key
        long xorMagic = buffer.getUnsignedInt(0);
        xorMagic ^= BytesUtil.int2UnsignedInt(PacketConst.HEADER_CONST);
        String keyBase64 = kcpAnalyzeConfig.XorKeys.get(xorMagic);
        if (keyBase64 == null || keyBase64.isBlank()) {
            log.warn("无效Xor魔数键 => " + xorMagic);
            return null;
        }

        try {
            // 异或解密数据
            byte[] key = Base64.getDecoder().decode(keyBase64);
            CryptoHelper.xorDecrypt(buffer, key);
        } catch (IllegalArgumentException e) {
            log.warn("无效的xor密钥", e);
            return null;
        }

        return buffer;
    }

    /**
     * 解析KCP数据包
     *
     * @param packet KCP数据包字节对象
     * @return protobuf内容字节数组
     */
    private byte[] parseKcpPacket(ByteBuf packet) {
        // 长度
        if (packet.readableBytes() < 16) {
            return null;
        }

        // 数据包头部检查
        int constHeader = packet.readInt();
        if (constHeader != PacketConst.HEADER_CONST) {
            return null;
        }

        // 数据信息
        int cmdId = packet.readShort(); // 指令值
        int headerLength = packet.readShort(); // kcp头部长度
        int dataLength = packet.readInt(); // protobuf内容长度

        // protobuf内容读取
        byte[] proto = new byte[dataLength];
        packet.skipBytes(headerLength);
        packet.readBytes(proto);

        // 数据包尾部检查
        int constTail = packet.readInt();
        if (constTail != PacketConst.TAIL_CONST) {
            return null;
        }

        if (loggingConfig.EnableKcpAnalyzeHint) {
            log.info("[" + sender +"]发送CmdId => " + cmdId);
        }

        return proto;
    }

    /**
     * 解析未知Protobuf消息
     * @param proto Protobuf消息字节
     * @return Protobuf消息数据类
     */
    public ProtoMessage parseUnknownProto(byte[] proto) {
        try {
            EmptyMessage msg = EmptyMessage.parseFrom(proto);

            ProtoMessage message = new ProtoMessage();
            message.parseFrom(msg.getUnknownFields());

            return message;
        } catch (InvalidProtocolBufferException e) {
            log.warn("无效的Protobuf字节", e);
        }

        return null;
    }
}
