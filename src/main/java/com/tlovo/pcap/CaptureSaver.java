package com.tlovo.pcap;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter.Feature;
import com.tlovo.pcap.data.CaptureData;
import com.tlovo.util.PathUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 捕获数据保存服务
 */
@Slf4j
public class CaptureSaver {
    private final static String filePrefix = "capture_";

    /** 保存间隔 */
    private final int interval;

    /** 等待保存列表 */
    private final ConcurrentHashMap<Long, CaptureData> waitList;
    private long index;
    private FileWriter fileWriter;
    private Timer timer;

    /**
     * @param interval 保存间隔（秒）
     */
    public CaptureSaver(int interval) {
        this.interval = interval;
        this.waitList = new ConcurrentHashMap<>();
        this.index = 1;
    }

    /**
     * 启动捕获保存服务
     */
    public void start(){
        if (!fileCheck()) return;
        if (timer != null) return;

        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                save();
            }
        };

        timer = new Timer();
        long inv = interval * 1000L;
        timer.scheduleAtFixedRate(task, inv, inv);
    }

    /**
     * 停止捕获保存服务
     */
    public void stop() {
        if (timer == null) return;
        timer.cancel();

        save();
        if (fileWriter != null) {
            try {
                fileWriter.close();
            } catch (IOException ignored) {}
        }
    }

    /**
     * 保存文件检查
     * @return 是否检查成功
     */
    private boolean fileCheck() {
        String path = PathUtil.CapturePath + "/" + filePrefix + System.currentTimeMillis() + ".json";
        try {
            File file = new File(path);
            if (!file.exists()) {
                if (!file.createNewFile()) {
                    throw new IOException("无法创建捕获文件");
                }
                fileWriter = new FileWriter(file, false);
            } else {
                throw new IOException("捕获文件已存在");
            }
        } catch (IOException e) {
            log.error("无效的捕获文件保存位置", e);
            return false;
        }

        return true;
    }

    /**
     * 将捕获数据添加到等待保存队列
     * @param data 要添加的捕获数据
     */
    public void add2Save(CaptureData data) {
        waitList.put(index++, data);
    }

    /**
     * 将等待保存列表里的所有数据保存到捕获文件中
     */
    private void save() {
        String json = JSON.toJSONString(waitList, Feature.PrettyFormat);
        try {
            fileWriter.write(json);
        } catch (IOException e) {
            log.warn("保存捕获数据发生异常", e);
        }
    }
}
