package com.tlovo;


import com.tlovo.pcap.UdpCapture;
import com.tlovo.pcap.UdpPacketListener;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import java.util.List;
import java.util.Scanner;

@Slf4j
public class MhuoUdpSniffer {
    private static Scanner consoleReader;
    private static PcapNetworkInterface networkInterface;
    private static UdpCapture captureThread;

    public static void main(String[] args) {
        consoleReader = new Scanner(System.in);

        networkInterface = selectInterface();
        if (networkInterface == null) {
            log.error("网络设备未选择正确");
            return;
        }

        captureThread = new UdpCapture(networkInterface);
        log.info("开始捕获...");
        captureThread.start();
    }

    /**
     * 选择要监听的网络设备
     * @return 选择的网络设备对象
     */
    private static PcapNetworkInterface selectInterface() {
        try {
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

            for (int i = 0; i < devices.size(); i++) {
                var device = devices.get(i);
                System.out.println("[" + i + "] " + device.getDescription());
            }

            System.out.print("请选择要监听的网络设备：");
            return devices.get(consoleReader.nextInt());
        } catch (PcapNativeException e) {
            log.error("查找网络设备时发生异常", e);
        } catch (IndexOutOfBoundsException e) {
            log.error("无效设备索引");
        }

        return null;
    }
}