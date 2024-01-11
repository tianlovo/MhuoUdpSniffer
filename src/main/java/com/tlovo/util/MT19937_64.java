package com.tlovo.util;

public class MT19937_64 {
    private static final int NN = 312;
    private static final int MM = 156;
    private static final long MATRIX_A = 0xB5026F5AA96619E9L;
    private static final long UM = 0xFFFFFFFF80000000L; // Most significant 33 bits
    private static final long LM = 0x7FFFFFFFL; // Least significant 31 bits

    private final long[] mt;
    private int mti;

    /**
     * 使用随机种子创建随机数生成器
     * @param seed MT19937_64随机数生成器
     */
    @SuppressWarnings("unused")
    public MT19937_64(long seed) {
        mt = new long[NN];
        mti = NN + 1;
        mt[0] = seed;

        for (mti = 1; mti < NN; mti++) {
            mt[mti] = (6364136223846793005L * (mt[mti - 1] ^ (mt[mti - 1] >>> 62)) + mti);
        }
    }

    /**
     * 生成随机long型数值
     * @return 随机long型数值
     */
    public long nextLong() {
        if (mti >= NN) {
            twist();
        }

        long y = mt[mti++];
        y ^= (y >>> 29) & 0x5555555555555555L;
        y ^= (y << 17) & 0x71D67FFFEDA60000L;
        y ^= (y << 37) & 0xFFF7EEE000000000L;
        y ^= (y >>> 43);

        return y;
    }

    private void twist() {
        for (int i = 0; i < NN; i++) {
            long x = (mt[i] & UM) | (mt[(i + 1) % NN] & LM);
            mt[i] = mt[(i + MM) % NN] ^ (x >>> 1) ^ (x & 1L) * MATRIX_A;
        }

        mti = 0;
    }
}
