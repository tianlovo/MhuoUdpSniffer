package com.tlovo.analyze;

import com.google.protobuf.InvalidProtocolBufferException;
import com.tlovo.MhuoUdpSniffer;
import com.tlovo.analyze.packet.CmdId;
import com.tlovo.analyze.packet.PacketConst;
import com.tlovo.analyze.packet.ProtoMessage;
import com.tlovo.config.data.KcpAnalyzeConfig;
import com.tlovo.config.data.LoggingConfig;
import com.tlovo.proto.EmptyMessageOuterClass.EmptyMessage;
import com.tlovo.proto.PlayerGetTokenScRspOuterClass.PlayerGetTokenScRsp;
import com.tlovo.util.BytesUtil;
import com.tlovo.util.CryptoHelper;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

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
    private final byte[] udpRawData;

    /** KCP分析配置 */
    private final KcpAnalyzeConfig kcpAnalyzeConfig;
    /** 日志配置 */
    private final LoggingConfig loggingConfig;

    /** 解密proto数据的xor密钥 */
    private static byte[] sessionKey;

    private int cmdId;

    public KcpAnalyzer(String sender, byte[] udpRawData) {
        this.sender = sender;
        this.udpRawData = udpRawData;
        this.kcpAnalyzeConfig = MhuoUdpSniffer.getKcpAnalyzeConfig();
        this.loggingConfig = MhuoUdpSniffer.getLoggingConfig();
    }

    @Override
    public void run() {
        ByteBuf kcpBuf = decryptUdpPayload();
        if (kcpBuf != null) {
            byte[] proto = parseKcpPacket(kcpBuf);
            kcpBuf.release();

            // TODO 处理消息
//            ProtoMessage msg = parseUnknownProto(proto);
//            if (msg != null) {
//            }
        }
    }

    /**
     * 解密Udp负载
     */
    private ByteBuf decryptUdpPayload() {
        final int udpHeader = 8, kcpHeader = 28;
        if (sessionKey == null) {
            log.info("解析会话密钥...");
            sessionKey = parseSessionKey(udpRawData);
            if (sessionKey != null) {
                log.info("会话密钥解析成功 => " + Base64.getEncoder().encodeToString(sessionKey));
            } else {
                log.warn("会话密钥解析失败");
                return null;
            }
        }

        // xor解密数据包
        byte[] xorData = Arrays.copyOfRange(udpRawData, udpHeader + kcpHeader, udpRawData.length);
        CryptoHelper.xorDecrypt(xorData, sessionKey);

        return PooledByteBufAllocator.DEFAULT.buffer().writeBytes(xorData);
    }

    /**
     * 从PlayerGetTokenScRsp包中获取密钥的随机种子
     * @param udpRawData udp数据包字节数组
     * @return 密钥的随机种子创建的xor pad
     */
    private byte[] parseSessionKey(byte[] udpRawData) {
        final int udpHeader = 8, kcpHeader = 28;
        if (udpRawData.length <= udpHeader + kcpHeader) return null;

        byte[] xorEncryptData = Arrays.copyOfRange(udpRawData, udpHeader + kcpHeader, udpRawData.length);
        ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(xorEncryptData);
        int xorMagic = buffer.getInt(0);
        xorMagic ^= PacketConst.HEADER_CONST;

        String dispatchKey = kcpAnalyzeConfig.XorKeys.get((long) xorMagic);
        byte[] dispatchKeyData = Base64.getDecoder().decode(dispatchKey);
        CryptoHelper.xorDecrypt(buffer, dispatchKeyData);

        int constHeader = buffer.readInt();
        if (constHeader != PacketConst.HEADER_CONST) {
            log.error("魔数头部不匹配 => " + constHeader);
            return null;
        }

        int cmdId = buffer.readShort(); // 指令值
        int headerLength = buffer.readShort(); // kcp头部长度
        int dataLength = buffer.readInt(); // protobuf内容长度

        // 只有PlayerGetTokenScRsp包里有密钥随机种子
        if (cmdId != CmdId.PlayerGetTokenScRsp) {
            return null;
        }

        byte[] proto = new byte[dataLength];
        buffer.skipBytes(headerLength);
        buffer.readBytes(proto);

        buffer.release();

        PlayerGetTokenScRsp playerGetTokenScRsp;
        try {
            playerGetTokenScRsp = PlayerGetTokenScRsp.parseFrom(proto);
        } catch (InvalidProtocolBufferException e) {
            log.error("无效PlayerGetTokenScRsp字节数组", e);
            return null;
        }

        long keySeed = playerGetTokenScRsp.getSecretKeySeed();
        return CryptoHelper.createXorPad(keySeed);
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
            // TODO 是否打印非protobuf数据包错误信息 配置
            // log.error("魔数头部不匹配 => 0x" + "%02x".formatted(constHeader).toUpperCase());
            return null;
        }


        // 数据信息
        cmdId = packet.readShort(); // 指令值
        int headerLength = packet.readShort(); // kcp头部长度
        int dataLength = packet.readInt(); // protobuf内容长度

        // protobuf内容读取
        byte[] proto = new byte[dataLength];
        packet.skipBytes(headerLength);
        packet.readBytes(proto);

        // 数据包尾部检查
        int constTail = packet.readInt();
        if (constTail != PacketConst.TAIL_CONST) {
            // TODO 是否打印非protobuf数据包错误信息 配置
            // log.error("异常尾部 => 0x" + "%02x".formatted(constHeader).toUpperCase());
            return null;
        }

        if (loggingConfig.EnableKcpAnalyzeHint) {
            Map<Integer, String> cmdIds = MhuoUdpSniffer.getCmdIds();
            if (cmdIds != null && cmdIds.containsKey(cmdId)) {
                log.info("[" + sender +"]发送 => " + cmdIds.get(cmdId));
            } else {
                log.info("[" + sender +"]发送 CmdId => " + cmdId);
            }
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

            ProtoMessage message;

            Map<Integer, String> cmdIds = MhuoUdpSniffer.getCmdIds();
            if (cmdIds != null && cmdIds.containsKey(cmdId)) {
                message = new ProtoMessage(cmdIds.get(cmdId));
            } else {
                message = new ProtoMessage(String.valueOf(cmdId));
            }

            message.parseFrom(msg.getUnknownFields());

            return message;
        } catch (InvalidProtocolBufferException e) {
            log.warn("无效的Protobuf字节", e);
        }

        return null;
    }
}
