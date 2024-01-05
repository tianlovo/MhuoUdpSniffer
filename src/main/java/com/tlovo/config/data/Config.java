package com.tlovo.config.data;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import com.tlovo.config.Configure;
import com.tlovo.util.PathUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

@Slf4j
public abstract class Config implements Configure {
    public abstract String GetConfigName();

    protected abstract File getFile();
    protected abstract void setFile(File file);

    public abstract boolean load();

    @Override
    public boolean save() {
        if (getFile() == null) {
            log.warn("保存配置失败，文件对象不存在");
            return false;
        }

        try (FileWriter writer = new FileWriter(getFile(), false)) {
            writer.write(JSON.toJSONString(this, JSONWriter.Feature.PrettyFormat));
        } catch (IOException e) {
            log.warn("写入配置文件发生错误", e);
            return false;
        }

        return true;
    }

    /**
     * 检查配置并判断是否需要读取配置文件
     * @return 是否读取配置文件
     */
    public boolean fileCheckRead() {
        if (getFile() != null) return true;

        String path = PathUtil.ConfigPath + "/" + GetConfigName();
        boolean read = true;

        setFile(new File(path));

        if (!getFile().exists()) {
            read = false;
            log.warn(path + " 配置不存在，自动创建默认配置");
            save();
        }

        return read;
    }
}
