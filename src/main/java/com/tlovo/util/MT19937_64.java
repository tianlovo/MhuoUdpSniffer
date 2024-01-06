package com.tlovo.util;

public class MT19937_64 {
    private static final int N = 312;
    private static final int M = 156;
    private static final long MATRIX_A = 0xB5026F5AA96619E9L;
    private static final long UPPER_MASK = 0xFFFFFFFF80000000L;
    private static final long LOWER_MASK = 0x7FFFFFFFL;

    private final long[] array;
    private int index;

    public MT19937_64() {
        this.index = N + 1;
        this.array = new long[N];
    }

    public void seed(long seed) {
        this.array[0] = seed;
        for (this.index = 1; this.index < N; this.index++) {
            this.array[this.index] = (6364136223846793005L *
                    (this.array[this.index - 1] ^ (this.array[this.index - 1] >>> 62))
                    + this.index
            );
        }
    }

    public long generate() {
        return int63();
    }

    public long int63() {
        int i;
        long x;
        long[] mag01 = {0L, MATRIX_A};
        if (this.index >= N) {
            if (this.index == N + 1) {
                seed(5489L);
            }

            for (i = 0; i < N - M; i++) {
                x = (this.array[i] & UPPER_MASK) | (this.array[i + 1] & LOWER_MASK);
                this.array[i] = this.array[i + (M)] ^ (x >>> 1) ^ mag01[(int) (x & 1)];
            }
            for (; i < N - 1; i++) {
                x = (this.array[i] & UPPER_MASK) | (this.array[i + 1] & LOWER_MASK);
                this.array[i] = this.array[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1)];
            }
            x = (this.array[N - 1] & UPPER_MASK) | (this.array[0] & LOWER_MASK);
            this.array[N - 1] = this.array[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1)];
            this.index = 0;
        }
        x = this.array[this.index];
        this.index++;
        x ^= (x >> 29) & 0x5555555555555555L;
        x ^= (x << 17) & 0x71D67FFFEDA60000L;
        x ^= (x << 37) & 0xFFF7EEE000000000L;
        x ^= (x >> 43);

        return x;
    }
}
