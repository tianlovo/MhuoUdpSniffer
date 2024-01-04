package com.tlovo.service;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * UDP转发服务
 */
@Slf4j
public class UdpRepeatService {
    @Getter private final InetAddress repeatTarAddr;
    @Getter private final int repeatTarPort;
    private final DatagramSocket socket;

    public UdpRepeatService(InetAddress repeatTarAddr, int repeatTarPort) {
        this.repeatTarAddr = repeatTarAddr;
        this.repeatTarPort = repeatTarPort;
        this.socket = createSocket();
    }

    private DatagramSocket createSocket() {
        try {
            return new DatagramSocket(repeatTarPort, repeatTarAddr);
        } catch (SocketException e) {
            throw new RuntimeException("连接目标服务器异常", e);
        }
    }

    /**
     * 转发UDP至目标服务器
     * @param payload UDP数据包负载
     */
    public void repeat(byte[] payload) {
        DatagramPacket packet = new DatagramPacket(payload, payload.length, repeatTarAddr, repeatTarPort);

        Runnable sendTask = () -> {
            try {
                socket.send(packet);
            } catch (IOException e) {
                throw new RuntimeException("UDP数据包转发发生异常", e);
            }
        };

        // 使用线程池执行任务
        // 这里使用了单线程的线程池，可以根据需要使用自定义的线程池
        ExecutorService executorService = Executors.newCachedThreadPool();
        executorService.execute(sendTask);

        // 关闭线程池
        executorService.shutdown();
    }
}
