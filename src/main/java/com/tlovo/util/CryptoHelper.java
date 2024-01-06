package com.tlovo.util;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;

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

    /**
     * 通过随机数种子生成xor pad
     * @param seed 随机数种子
     * @return xor pad
     */
    public static byte[] createXorPad(long seed) {
        MT19937_64 rand = new MT19937_64();
        rand.seed(seed);

        ByteBuf xorPad = PooledByteBufAllocator.DEFAULT.buffer(4096);

        for (int i = 0; i < 4096; i+=8) {
            xorPad.writeLong(rand.generate());
        }

        return BytesUtil.directBufferToByteArray(xorPad);
    }
}
