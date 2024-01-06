package com.tlovo;

import com.tlovo.config.data.CaptureConfig;
import com.tlovo.config.data.KcpAnalyzeConfig;
import com.tlovo.config.data.LoggingConfig;
import com.tlovo.pcap.UdpCapture;
import com.tlovo.util.Utils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.util.List;
import java.util.Map;

@Slf4j
public class MhuoUdpSniffer {
    private static PcapNetworkInterface networkInterface;
    private static UdpCapture captureThread;

    // ===== Config =====
    @Getter private static CaptureConfig captureConfig;
    @Getter private static KcpAnalyzeConfig kcpAnalyzeConfig;
    @Getter private static LoggingConfig loggingConfig;

    @Getter private static Map<Integer, String> cmdIds;

    public static void main(String[] args) {
        // 添加程序关闭事件
        Runtime.getRuntime().addShutdownHook(new Thread(MhuoUdpSniffer::onShutdown));

        // 配置文件初始化
        loadConfig();

        // CmdId指令集
        if (captureConfig.EnableKcpAnalyze) {
            cmdIds = Utils.extractCmdIds();
        }

        // 网络设备初始化
        try {
            LinkLayerAddress findMac = LinkLayerAddress.getByName(captureConfig.BindDeviceMac);
            List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

            devices.forEach(inter -> {
                if (inter.getLinkLayerAddresses().contains(findMac)) {
                    networkInterface = inter;
                }
            });

            if (networkInterface == null) {
                throw new PcapNativeException("无效的网络设备Mac地址");
            }
        } catch (PcapNativeException e) {
            log.error("查找网络设备时发生异常", e);
        }

        // 捕获线程初始化
        captureThread = new UdpCapture(networkInterface);

        log.info("开始捕获...");
        captureThread.start();
    }

    /**
     * 程序关闭自动调用
     */
    private static void onShutdown() {
        if (captureThread != null) {
            captureThread.onShutdown();
        }
    }

    /**
     * 加载配置文件
     */
    private static void loadConfig() {
        captureConfig = new CaptureConfig();
        if (!captureConfig.load()) {
            log.warn("配置文件加载失败 => " + captureConfig.GetConfigName());
        }

        kcpAnalyzeConfig = new KcpAnalyzeConfig();
        if (!kcpAnalyzeConfig.load()) {
            log.warn("配置文件加载失败 => " + kcpAnalyzeConfig.GetConfigName());
        }

        loggingConfig = new LoggingConfig();
        if (!loggingConfig.load()) {
            log.warn("配置文件加载失败 => " + loggingConfig.GetConfigName());
        }
    }
}