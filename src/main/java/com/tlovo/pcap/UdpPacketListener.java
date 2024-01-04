package com.tlovo.pcap;

import com.tlovo.service.UdpRepeatService;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

/**
 * Udp数据包监听器
 */
@Slf4j
public class UdpPacketListener implements PacketListener {
    private UdpRepeatService repeater;

    public UdpPacketListener() {
    }

    public UdpPacketListener(UdpRepeatService repeater) {
        this.repeater = repeater;
    }

    /**
     * 接收到数据包时自动调用
     * @param packet 接收到的数据包
     */
    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            byte[] payload = udpPacket.getPayload().getRawData();

            if (repeater != null) {
                log.info("转发UDP[" + payload.length + "字节] => " +
                        repeater.getRepeatTarAddr() + ":" + repeater.getRepeatTarPort());
                repeater.repeat(payload);
            } else {
                log.info("捕获UDP => " + payload.length + "字节");
            }
        }
    }
}
