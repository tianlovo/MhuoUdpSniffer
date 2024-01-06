package com.tlovo.config.data;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 捕获配置数据类
 */
@Slf4j
@EqualsAndHashCode(callSuper = true)
public class CaptureConfig extends Config {
    /**
     * 绑定监听的网络设备Mac地址
     */
    @JSONField(name = "bind_device_mac")
    public String BindDeviceMac = "";

    /**
     * 每个数据包的最大长度
     */
    @JSONField(name = "per_max_length")
    public int PerMaxLength = 1024 * 1024; // 1MB

    /**
     * 指定捕获数据包的超时时间(毫秒)
     */
    @JSONField(name = "timeout")
    public int Timeout = 10 * 1000; // 10s

    /**
     * 捕获模式
     */
    @JSONField(name = "capture_mode")
    public PromiscuousMode CaptureMode = PromiscuousMode.NONPROMISCUOUS; // 非混杂模式，仅捕获指定设备的流量

    /**
     * 捕获服务器端口列表（包括源和目标端口）
     * <br/>
     * -1为捕获所有端口
     */
    @JSONField(name = "server_port_list")
    public List<Short> ServerPortList = new ArrayList<>(List.of((short) 23301, (short) 23302));

    /**
     * 是否启用Kcp分析服务
     */
    @JSONField(name = "enable_kcp_analyze")
    public boolean EnableKcpAnalyze = false;

    /**
     * 是否保存捕获数据
     */
    @JSONField(name = "auto_save_capture")
    public boolean AutoSaveCapture = true;

    /**
     * 保存捕获数据间隔（秒）
     */
    @JSONField(name = "save_capture_interval")
    public int SaveCaptureInterval = 5;

    @Getter
    @Setter(AccessLevel.PROTECTED)
    private transient File file;

    @Override
    public String GetConfigName() {
        return "capture_config.json";
    }

    @Override
    public boolean load() {
        if (fileCheckRead()) {
            try (FileInputStream stream = new FileInputStream(file)) {
                CaptureConfig config = JSON.parseObject(stream.readAllBytes(), CaptureConfig.class);
                BindDeviceMac = config.BindDeviceMac;
                PerMaxLength = config.PerMaxLength;
                Timeout = config.Timeout;
                CaptureMode = config.CaptureMode;
                EnableKcpAnalyze = config.EnableKcpAnalyze;
                ServerPortList = config.ServerPortList;
                AutoSaveCapture = config.AutoSaveCapture;
                SaveCaptureInterval = config.SaveCaptureInterval;
            } catch (IOException e) {
                log.warn("读取文件发生错误", e);
                return false;
            }
        }

        return true;
    }
}
