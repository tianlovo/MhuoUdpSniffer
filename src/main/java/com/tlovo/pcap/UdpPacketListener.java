package com.tlovo.pcap;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

/**
 * Udp数据包监听器
 */
@Slf4j
public class UdpPacketListener implements PacketListener {
    /**
     * 接收到数据包时自动调用
     * @param packet 接收到的数据包
     */
    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            byte[] payload = udpPacket.getPayload().getRawData();
            log.debug("捕获UDP => " + payload.length);
        }
    }
}
