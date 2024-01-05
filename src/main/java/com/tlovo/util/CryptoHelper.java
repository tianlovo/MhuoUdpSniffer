package com.tlovo.util;

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
}
