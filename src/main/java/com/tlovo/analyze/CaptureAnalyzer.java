package com.tlovo.analyze;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.TypeReference;
import com.google.protobuf.InvalidProtocolBufferException;
import com.tlovo.MhuoUdpSniffer;
import com.tlovo.analyze.packet.*;
import com.tlovo.pcap.data.CaptureData;
import com.tlovo.proto.PlayerGetTokenScRspOuterClass;
import com.tlovo.util.CryptoHelper;
import com.tlovo.util.PathUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 捕获文件解析器（.json）
 */
@Slf4j
public class CaptureAnalyzer {
    private final TreeMap<Long, CaptureData> captureMap;

    /** 解密kcp负载内容的xor密钥 */
    private byte[] sessionKey;

    public CaptureAnalyzer() {
        this.captureMap = new TreeMap<>();
    }

    /**
     * 开始分析捕获文件
     * @param fileName 捕获文件名称（不带.json后缀）
     */
    public void analyzer(String fileName) {
        // 初始化
        analyzeInit(fileName);

        // 关键数据判断
        if (captureMap.isEmpty()) {
            log.error("无捕获数据");
            return;
        }
        if (sessionKey == null) {
            log.error("解密kcp负载内容的xor密钥不存在，无法解析");
            return;
        }

        // 过滤
        filterCaptureMap();
        printCmdId();
    }

    /**
     * 分析前的初始化
     * @param fileName 要分析的文件名称
     */
    private void analyzeInit(String fileName) {
        var kcpAnalyzeConfig = MhuoUdpSniffer.getKcpAnalyzeConfig();
        String path = PathUtil.CapturePath + "/" + fileName + ".json";

        // 读取文件
        String json = readFile(path);
        if (json == null) return;

        // json反序列化
        TypeReference<HashMap<String, CaptureData>> typeRef = new TypeReference<>() {
        };
        HashMap<String, CaptureData> map = JSON.parseObject(json, typeRef);

        // 将HashMap按照String键的long值进行排序
        captureMap.clear();
        for (Map.Entry<String, CaptureData> entry : map.entrySet()) {
            long keyAsLong = Long.parseLong(entry.getKey());
            captureMap.put(keyAsLong, entry.getValue());
        }

        // 多个PlayerGetTokenScRsp获取sessionKey
        for (Long index : captureMap.keySet()) {
            byte[] decode = Base64.getDecoder().decode(captureMap.get(index).UdpData);
            if (decode.length > 36) {
                ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer().writeBytes(decode);
                buffer.skipBytes(36);

                int xorMagic = buffer.getInt(buffer.readerIndex());
                xorMagic ^= PacketConst.HEADER_CONST;
                if (kcpAnalyzeConfig.XorKeys.containsKey((long) xorMagic)) {
                    String lastDKey = kcpAnalyzeConfig.XorKeys.get((long) xorMagic);
                    ByteBuf lastSeedPacket = buffer.copy(buffer.readerIndex(), buffer.readableBytes());
                    parseSessionKey(lastDKey, lastSeedPacket);
                }

                buffer.release();
            }
        }
    }

    /**
     * 读取json文件
     * @param path 文件全路径
     * @return 读取的字符串（UTF8）
     */
    private String readFile(String path) {
        byte[] fileBytes;
        try {
            fileBytes = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            log.error("读取文件发生异常", e);
            return null;
        }
        return new String(fileBytes, StandardCharsets.UTF_8);
    }

    /**
     * 解析并获取会话密钥
     * @param dispatchKey 分发服务器密钥
     * @param seedPacket 有secret_key_seed的protobuf数据包字节
     */
    private void parseSessionKey(String dispatchKey, ByteBuf seedPacket) {
        byte[] dKeyData = Base64.getDecoder().decode(dispatchKey);
        CryptoHelper.xorDecrypt(seedPacket, dKeyData);

        int constHeader = seedPacket.readInt();
        if (constHeader != PacketConst.HEADER_CONST) {
            log.error("魔数头部不匹配 => " + constHeader);
        } else {
            int cmdId = seedPacket.readShort(); // 指令值
            int headerLength = seedPacket.readShort(); // kcp头部长度
            int dataLength = seedPacket.readInt(); // protobuf内容长度

            // 只有PlayerGetTokenScRsp包里有密钥随机种子
            if (cmdId == CmdId.PlayerGetTokenScRsp) {
                byte[] proto = new byte[dataLength];
                seedPacket.skipBytes(headerLength);
                seedPacket.readBytes(proto);

                seedPacket.release();

                PlayerGetTokenScRspOuterClass.PlayerGetTokenScRsp playerGetTokenScRsp;
                try {
                    playerGetTokenScRsp = PlayerGetTokenScRspOuterClass.PlayerGetTokenScRsp.parseFrom(proto);
                    long keySeed = playerGetTokenScRsp.getSecretKeySeed();
                    sessionKey = CryptoHelper.createXorPad(keySeed);
                } catch (InvalidProtocolBufferException e) {
                    log.error("无效PlayerGetTokenScRsp字节数组", e);
                }
            }
        }
    }

    /**
     * 过滤捕获Map
     */
    private void filterCaptureMap() {
        for (int i = 0; i < captureMap.keySet().toArray().length; i++) {
            Long index = (Long) captureMap.keySet().toArray()[i];
            CaptureData captureData = captureMap.get(index);

            byte[] decode = Base64.getDecoder().decode(captureData.UdpData);
            Udp udp = Udp.parse(decode, sessionKey);

            // 不是kcp和没有protobuf内容的 移除
            if (udp == null || udp.getKcp() == null || udp.getKcp().getProtoPacket() == null) {
                captureMap.remove(index);
                continue;
            }

            // kcp命令不是CMD_PUSH（数据包类型）的 移除
            if (udp.getKcp().getCmd() != 81) {
                captureMap.remove(index);
                continue;
            }
        }
    }

    /**
     * 打印cmdId
     */
    private void printCmdId() {
        AtomicInteger c = new AtomicInteger();
        captureMap.forEach((index, data) -> {
            byte[] decode = Base64.getDecoder().decode(data.UdpData);
            Udp udp = Udp.parse(decode, sessionKey);

            if (udp != null && udp.getKcp() != null && udp.getKcp().getProtoPacket() != null) {
                ProtoPacket packet = udp.getKcp().getProtoPacket();
                Map<Integer, String> cmdIds = MhuoUdpSniffer.getCmdIds();
                int cmdId = packet.getCmdId();
                log.info("cmdId => " + (cmdIds.get(cmdId) == null ? cmdId : cmdIds.get(cmdId)));
                c.getAndIncrement();
            }
        });
    }
}
