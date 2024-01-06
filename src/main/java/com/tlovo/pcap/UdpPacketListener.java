package com.tlovo.pcap;

import com.tlovo.MhuoUdpSniffer;
import com.tlovo.analyze.KcpAnalyzer;
import com.tlovo.config.data.CaptureConfig;
import com.tlovo.config.data.LoggingConfig;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UdpPacket.UdpHeader;

import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Udp数据包监听器
 */
@Slf4j
public class UdpPacketListener implements PacketListener {
    /** 解析数据包线程池 */
    private final ExecutorService packetParsePool;


    public UdpPacketListener(ExecutorService packetParsePool) {
        this.packetParsePool = packetParsePool;
    }

    /**
     * 接收到数据包时自动调用
     * @param packet 接收到的数据包
     */
    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(UdpPacket.class)) {
            CaptureConfig captureConfig = MhuoUdpSniffer.getCaptureConfig();
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            UdpHeader header = udpPacket.getHeader();
            String sender = "";

            // 端口判断
            List<Short> portList = captureConfig.ServerPortList;
            // 如果有-1端口则代表捕获全部端口
            if (portList.contains((short) -1)) {
                sender = "Server/Client";
            } else {
                // 客户端 向 服务器 发送数据包
                if (portList.contains(header.getDstPort().value())) {
                    sender = "Client";
                }
                // 服务端 向 客户端 发送数据包
                else if (portList.contains(header.getSrcPort().value())) {
                    sender = "Server";
                }
            }

            // 处理数据包
            handlePacket(udpPacket.getRawData(), sender);
        }
    }

    private void handlePacket(byte[] rawData, String sender) {
        if (sender.isBlank()) return;

        CaptureConfig captureConfig = MhuoUdpSniffer.getCaptureConfig();
        LoggingConfig loggingConfig = MhuoUdpSniffer.getLoggingConfig();

        if (loggingConfig.EnableCapturedHint) {
            log.info("捕获UDP => " + rawData.length + "字节");
        }

        // 分析KCP数据
        if (captureConfig.EnableKcpAnalyze) {
            packetParsePool.submit(new KcpAnalyzer(sender, rawData));
        }
    }

    /**
     * 监听器关闭事件
     */
    public void onShutdown() {
        if (packetParsePool != null) {
            packetParsePool.shutdown();
        }
    }
}
