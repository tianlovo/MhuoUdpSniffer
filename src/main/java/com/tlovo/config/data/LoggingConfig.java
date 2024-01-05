package com.tlovo.config.data;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@Slf4j
public class LoggingConfig extends Config {
    /**
     * 是否打印捕获提示
     */
    @JSONField(name = "enable_captured_hint")
    public boolean EnableCapturedHint = false;

    /**
     * 是否打印Kcp解析信息
     */
    @JSONField(name = "enable_kcp_analyze_hint")
    public boolean EnableKcpAnalyzeHint = true;

    @Getter
    @Setter(AccessLevel.PROTECTED)
    private transient File file;

    @Override
    public String GetConfigName() {
        return "logging_config.json";
    }

    @Override
    public boolean load() {
        if (fileCheckRead()) {
            try (FileInputStream stream = new FileInputStream(file)) {
                LoggingConfig config =
                        JSON.parseObject(stream.readAllBytes(), LoggingConfig.class);
                EnableCapturedHint = config.EnableCapturedHint;
            } catch (IOException e) {
                log.warn("读取文件发生错误", e);
                return false;
            }
        }

        return true;
    }
}
