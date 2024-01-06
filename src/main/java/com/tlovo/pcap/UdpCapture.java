package com.tlovo.pcap;

import com.tlovo.MhuoUdpSniffer;
import com.tlovo.config.data.CaptureConfig;
import com.tlovo.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.concurrent.Executors;

/**
 * Udp捕获器
 */
@Slf4j
public class UdpCapture extends Thread {
    private static final String THREAD_NAME = "Udp Capture";
    private final PcapNetworkInterface networkInterface;
    private final UdpPacketListener udpPacketListener;

    public UdpCapture(PcapNetworkInterface networkInterface) {
        this.networkInterface = networkInterface;
        this.udpPacketListener = new UdpPacketListener(Executors.newCachedThreadPool());
        setName(THREAD_NAME);
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
        CaptureConfig captureConfig = MhuoUdpSniffer.getCaptureConfig();

        try {
            try (PcapHandle pcap = networkInterface.openLive(
                    captureConfig.PerMaxLength,
                    captureConfig.CaptureMode,
                    captureConfig.Timeout
            )) {

                // 创建.pcap文件继续捕获数据保存
                if (captureConfig.AutoSaveCapture){
                    PcapDumper dumper = pcap.dumpOpen(PathUtil.CapturePath +
                            "/pcap/capture_" + System.currentTimeMillis() + ".pcap");
                    udpPacketListener.setDumper(dumper);
                }

                pcap.loop(-1, udpPacketListener);
            }
        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            log.error("捕获发生异常", e);
        }
    }

    /**
     * 线程关闭事件
     */
    public void onShutdown() {
        this.udpPacketListener.onShutdown();
        if (!this.isInterrupted()) {
            this.interrupt();
        }
    }
}
