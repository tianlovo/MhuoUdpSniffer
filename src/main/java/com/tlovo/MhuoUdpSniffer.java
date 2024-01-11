package com.tlovo;

import com.tlovo.analyze.CaptureAnalyzer;
import com.tlovo.config.data.CaptureConfig;
import com.tlovo.config.data.KcpAnalyzeConfig;
import com.tlovo.config.data.LoggingConfig;
import com.tlovo.emus.AppMode;
import com.tlovo.pcap.UdpCapture;
import com.tlovo.util.PathUtil;
import com.tlovo.util.Utils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.util.List;
import java.util.Map;
import java.util.Scanner;

@Slf4j
public class MhuoUdpSniffer {
    private static PcapNetworkInterface networkInterface;
    private static UdpCapture captureThread;

    // ===== Config =====
    @Getter
    private static CaptureConfig captureConfig;
    @Getter
    private static KcpAnalyzeConfig kcpAnalyzeConfig;
    @Getter
    private static LoggingConfig loggingConfig;

    @Getter
    private static Map<Integer, String> cmdIds;

    public static void main(String[] args) {
        // 添加程序关闭事件
        Runtime.getRuntime().addShutdownHook(new Thread(MhuoUdpSniffer::onShutdown));

        // 配置文件初始化
        loadConfig();

        // CmdId指令集
        if (captureConfig.EnableKcpAnalyze) {
            cmdIds = Utils.extractCmdIds();
        }

        // 选择启动模式
        switch (selectMode()) {
            case CAPTURE -> {
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
            // 分析捕获文件
            case ANAlYZE -> analyze();
        }
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

    /**
     * 选择当前APP启动模式
     *
     * @return 启动模式
     */
    private static AppMode selectMode() {
        Scanner sc = new Scanner(System.in);
        System.out.println("APP启动模式");
        for (int i = 0; i < AppMode.values().length; i++) {
            System.out.println("[" + (i + 1) + "] " + AppMode.values()[i]);
        }

        System.out.print("选择APP启动模式：");
        return AppMode.values()[sc.nextInt() - 1];
    }

    /**
     * 分析捕获存储文件（json）
     */
    private static void analyze() {
        Scanner sc = new Scanner(System.in);
        System.out.print("请输入要分析的文件名（不带后缀）：");

        // 获取指令集
        if (cmdIds == null) {
            cmdIds = Utils.extractCmdIds();
        }

        CaptureAnalyzer analyzer = new CaptureAnalyzer();
        analyzer.analyzer(sc.next());
    }
}