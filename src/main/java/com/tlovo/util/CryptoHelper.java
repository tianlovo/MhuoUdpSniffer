package com.tlovo.util;

import io.netty.buffer.ByteBuf;

/**
 * 加/解密帮助器
 */
public final class CryptoHelper {
    /**
     * 使用异或解密
     * @param data 要解密的字节数组
     * @param key 密钥字节数组
     */
    public static void xorDecrypt(byte[] data, byte[] key) {
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ key[i % key.length]);
        }
    }

    /**
     * 使用异或解密
     * @param data 要解密的ByteBuf
     * @param key 密钥字节数组
     */
    public static void xorDecrypt(ByteBuf data, byte[] key) {
        int dataLength = data.readableBytes();
        int keyLength = key.length;
        for (int i = 0; i < dataLength; i++) {
            byte dataByte = data.getByte(i);
            byte keyByte = key[i % keyLength];
            data.setByte(i, dataByte ^ keyByte);
        }
    }
}
