package com.kratos.dump;

/** Host-test twin of app/.../Native.kt: the same native signatures, loadable without Kotlin. */
public final class Native {
    private Native() {}

    public interface Listener {
        void onProgress(String stage, long done, long total, String text);
        void onLog(long tsMs, int level, String stage, String msg);
    }

    public static native String info();
    public static native String schema();
    public static native String validateConfig(String profile, String overrides);
    public static native String probeApk(int fd, String name, String profile, String overrides, String temp);
    public static native String probeLib(int fd, String name);
    public static native String probeMeta(int fd, String name);
    public static native String checkDir(String path);
    public static native long runNew();
    public static native void runCancel(long h);
    public static native void runDelete(long h);
    public static native String run(long h, String request, int apkFd, int libFd, int metaFd, Object listener);
}
