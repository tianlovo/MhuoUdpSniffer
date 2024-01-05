package com.tlovo.config;

/**
 * 可配置类接口
 */
public interface Configure {
    /**
     * @return 配置文件每次(包含后缀)
     */
    String GetConfigName();

    /**
     * 加载配置
     *
     * @return 是否成功加载配置
     */
    boolean load();

    /**
     * 保存配置
     *
     * @return 是否成功保持配置
     */
    boolean save();
}
