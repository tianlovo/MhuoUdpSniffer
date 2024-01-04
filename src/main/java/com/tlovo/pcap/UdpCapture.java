package com.tlovo.pcap;

import com.tlovo.service.UdpRepeatService;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import java.net.InetAddress;

/**
 * Udp捕获器
 */
@Slf4j
public class UdpCapture extends Thread {
    private static final String THREAD_NAME = "Udp Capture";

    private final int snapLen; // 1Mb 每个数据包的最大长度
    private final int timeout; // 10s 指定捕获数据包的超时时间(毫秒)
    private final PromiscuousMode mode; // 混杂模式，允许捕获网络上的所有流量，而不仅限于设备本身的流量
    private final PcapNetworkInterface networkInterface;

    private UdpRepeatService repeater;

    public UdpCapture(PcapNetworkInterface networkInterface) {
        this.networkInterface = networkInterface;
        snapLen = 1024 * 1024;
        timeout = 10 * 1000;
        mode = PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
        setName(THREAD_NAME);
    }

    public UdpCapture(PcapNetworkInterface networkInterface, int snapLen, PromiscuousMode mode, int timeout) {
        this.networkInterface = networkInterface;
        this.snapLen = snapLen;
        this.mode = mode;
        this.timeout = timeout;
        setName(THREAD_NAME);
    }

    /**
     * 设置UDP转发信息
     * @param repeatTargetAddr 转发目标IP地址
     * @param repeatTargetPort 转发目标端口
     */
    public void setRepeatInfo(InetAddress repeatTargetAddr, int repeatTargetPort) {
        repeater = new UdpRepeatService(repeatTargetAddr, repeatTargetPort);
    }

    /**
     * 启动Udp数据包捕获线程
     */
    @Override
    public synchronized void start() {
        super.start();
    }

    @Override
    public void run() {
        try {
            try (PcapHandle pcap = networkInterface.openLive(snapLen, mode, timeout)) {
                if (repeater != null) {
                    pcap.loop(-1, new UdpPacketListener(repeater));
                } else {
                    pcap.loop(-1, new UdpPacketListener());
                }
            }
        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            log.error("捕获发生异常", e);
        }
    }
}
