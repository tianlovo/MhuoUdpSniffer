package com.tlovo.util;

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
}
