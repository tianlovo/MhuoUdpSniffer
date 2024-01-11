package com.tlovo.util;

import io.netty.buffer.ByteBuf;

/**
 * 字节工具类
 */
public final class BytesUtil {
    /**
     * 十六进制字符串转字节数组
     * @param hexString 十六进制字符串
     * @return 字节数组
     */
    public static byte[] hexStringToByteArray(String hexString) {
        hexString = hexString.replaceAll("[,\\s]+", ""); // 移除逗号和空格

        int length = hexString.length();
        if (length % 2 != 0) {
            throw new IllegalArgumentException("输入的十六进制字符串长度不是偶数！");
        }

        byte[] result = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            result[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return result;
    }

    /**
     * 字节数组转十六进制字符串
     * @param byteArray 字节数组
     * @param hexPerLine 每行显示几个十六进制
     * @return 十六进制字符串
     */
    public static String byteArrayToHexString(byte[] byteArray, int hexPerLine) {
        StringBuilder hexString = new StringBuilder();
        int count = 0;

        for (byte b : byteArray) {
            hexString.append(String.format("%02X ", b));
            count++;

            if (count % hexPerLine == 0) {
                hexString.append("\n");
            }
        }

        return hexString.toString();
    }

    /**
     * Int32转无符号Int32
     * @param value Int32
     * @return 无符号Int32
     */
    public static long int2UnsignedInt(int value) {
        return value & 0xFFFFFFFFL;
    }

    /**
     * Netty的直接内存转为字节数组
     * @param buffer 直接内存
     * @return 字节数组
     */
    public static byte[] directBufferToByteArray(ByteBuf buffer) {
        byte[] bytes = new byte[buffer.readableBytes()];
        buffer.readBytes(bytes);
        return bytes;
    }

    /**
     * 将两个byte数组连接在一起，并返回新的数组。
     *
     * @param arrayA 第一个byte数组
     * @param arrayB 第二个byte数组
     * @return 连接后的新byte数组
     * @throws IllegalArgumentException 如果输入的数组任一为空
     */
    public static byte[] concatenateArrays(byte[] arrayA, byte[] arrayB) {
        if (arrayA == null || arrayB == null) {
            throw new IllegalArgumentException("输入的数组不能为null");
        }

        int lenA = arrayA.length;
        int lenB = arrayB.length;
        byte[] result = new byte[lenA + lenB];

        // 将数组A的内容复制到结果数组
        System.arraycopy(arrayA, 0, result, 0, lenA);

        // 将数组B的内容复制到结果数组的后面
        System.arraycopy(arrayB, 0, result, lenA, lenB);

        return result;
    }

}
