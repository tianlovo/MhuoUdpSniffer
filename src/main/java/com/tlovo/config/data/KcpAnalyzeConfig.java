package com.tlovo.config.data;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.annotation.JSONField;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

/**
 * Kcp分析服务配置数据类
 */
@Slf4j
@EqualsAndHashCode(callSuper = true)
public class KcpAnalyzeConfig extends Config {
    /**
     * 是否使用xor密钥解密数据
     */
    @JSONField(name = "use_xor_key")
    public boolean UseXorKey = true;

    /**
     * 异或魔数（十六进制字符串）
     */
    @JSONField(name = "hex_magic")
    public String HexMagic = "9d74c714";

    /**
     * xor密钥数据配置类
     */
    @JSONField(name = "xor_keys")
    public HashMap<Long, String> XorKeys = new HashMap<>();

    @Getter
    @Setter(AccessLevel.PROTECTED)
    private transient File file;

    @Override
    public String GetConfigName() {
        return "kcp_analyze_config.json";
    }

    @Override
    public boolean load() {
        if (fileCheckRead()) {
            try (FileInputStream stream = new FileInputStream(file)) {
                com.tlovo.config.data.KcpAnalyzeConfig config =
                        JSON.parseObject(stream.readAllBytes(), KcpAnalyzeConfig.class);
                UseXorKey = config.UseXorKey;
                HexMagic = config.HexMagic;
                XorKeys = config.XorKeys;
            } catch (IOException e) {
                log.warn("读取文件发生错误", e);
                return false;
            }
        }

        return true;
    }
}
