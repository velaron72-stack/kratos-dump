package com.kratos.dump

/** Receives progress and log entries from the analysis engine. Called from engine worker threads. */
interface NativeListener {
    fun onProgress(stage: String, done: Long, total: Long, text: String)

    /** level: 0 debug, 1 info, 2 ok, 3 warning, 4 error */
    fun onLog(tsMs: Long, level: Int, stage: String, msg: String)
}

/** JNI entry points of libkratos_jni.so. Every call returns JSON text; a failed call returns {"ok":false,"error":"..."}. */
object Native {
    @Volatile
    private var loaded = false

    @Volatile
    var loadError: String? = null
        private set

    /** Loads the native library once. Returns false (with [loadError] set) when it is not available for this device ABI. */
    @Synchronized
    fun ensureLoaded(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("kratos_jni")
            loaded = true
            true
        } catch (t: Throwable) {
            loadError = t.message ?: t.javaClass.simpleName
            false
        }
    }

    @JvmStatic external fun info(): String
    @JvmStatic external fun schema(): String
    @JvmStatic external fun validateConfig(profile: String, overrides: String): String
    @JvmStatic external fun probeApk(fd: Int, name: String, profile: String, overrides: String, tempDir: String): String
    @JvmStatic external fun probeLib(fd: Int, name: String): String
    @JvmStatic external fun probeMeta(fd: Int, name: String): String
    @JvmStatic external fun checkDir(path: String): String
    @JvmStatic external fun runNew(): Long
    @JvmStatic external fun runCancel(handle: Long)
    @JvmStatic external fun runDelete(handle: Long)
    @JvmStatic external fun run(handle: Long, request: String, apkFd: Int, libFd: Int, metaFd: Int, listener: NativeListener?): String
}
