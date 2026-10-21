import com.kratos.dump.Native;

import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.io.FileDescriptor;
import java.util.concurrent.atomic.AtomicInteger;

/** Loads the real JNI library into a JVM and drives it exactly as the Android app does. */
public final class JniSmokeTest {
    static int failures = 0;

    static void check(boolean ok, String what) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) failures++;
    }

    // Opens a file and returns its raw descriptor number (HotSpot/Linux).
    static int fdOf(FileInputStream in) throws Exception {
        Field f = FileDescriptor.class.getDeclaredField("fd");
        f.setAccessible(true);
        return f.getInt(in.getFD());
    }

    /** Listener implemented through the interface the Kotlin app uses (methods looked up by name and signature). */
    static final class L implements Native.Listener {
        final AtomicInteger progress = new AtomicInteger(), logs = new AtomicInteger();
        final StringBuilder cyr = new StringBuilder();
        public void onProgress(String stage, long done, long total, String text) { progress.incrementAndGet(); }
        public void onLog(long tsMs, int level, String stage, String msg) {
            logs.incrementAndGet();
            if (msg.chars().anyMatch(c -> c >= 0x400 && c < 0x500)) cyr.append(msg, 0, Math.min(40, msg.length()));
        }
    }

    public static void main(String[] a) throws Exception {
        String lib = a[0], fixtures = a[1], out = a[2];
        System.load(lib);
        String info = Native.info();
        check(info.contains("\"version\":\"1.0.0\"") && info.contains("capstone"), "info()");
        String schema = Native.schema();
        check(schema.contains("general.depth") && schema.contains("Быстрый"), "schema() carries Cyrillic text intact");
        String v = Native.validateConfig("standard", "{\"general.depth\":99}");
        check(v.contains("\"issues\":[{\"key\":\"general.depth\""), "validateConfig reports out-of-range value");

        try (FileInputStream apk = new FileInputStream(fixtures + "/sample_multi_abi.apk")) {
            String p = Native.probeApk(fdOf(apk), "sample_multi_abi.apk", "standard", "{}", out);
            check(p.contains("\"ok\":true") && p.contains("lib/arm64-v8a/libsample.so") && p.contains("armeabi-v7a"), "probeApk lists libraries per ABI");
        }
        try (FileInputStream so = new FileInputStream(fixtures + "/sample_arm64.so")) {
            check(Native.probeLib(fdOf(so), "sample_arm64.so").contains("\"arch\":\"arm64\""), "probeLib recognizes ARM64");
        }
        try (FileInputStream bad = new FileInputStream(fixtures + "/not_elf.so")) {
            check(Native.probeLib(fdOf(bad), "not_elf.so").contains("\"ok\":false"), "probeLib rejects a non-ELF file");
        }
        try (FileInputStream m = new FileInputStream(fixtures + "/global-metadata.dat")) {
            check(Native.probeMeta(fdOf(m), "global-metadata.dat").contains("\"recognized\":true"), "probeMeta recognizes IL2CPP metadata");
        }
        check(Native.checkDir(out).contains("\"writable\":true"), "checkDir on a writable directory");

        // Full run with callbacks arriving from engine worker threads, a non-BMP character and Cyrillic in the display name.
        long h = Native.runNew();
        L l = new L();
        String name = "тест 😀.apk";
        String req = "{\"mode\":\"apk\",\"display_name\":\"" + name + "\",\"out_root\":\"" + out + "\",\"profile\":\"quick\",\"temp_dir\":\"" + out + "\"}";
        String res;
        try (FileInputStream apk = new FileInputStream(fixtures + "/sample_multi_abi.apk")) {
            res = Native.run(h, req, fdOf(apk), -1, -1, l);
        }
        check(res.contains("\"status_id\":\"success\""), "run() finished with success");
        check(l.logs.get() > 10 && l.progress.get() > 0, "callbacks received (logs=" + l.logs.get() + ", progress=" + l.progress.get() + ")");
        check(res.contains("😀"), "supplementary-plane character survives the round trip");
        check(l.cyr.length() > 0, "Cyrillic log text survives the round trip");

        // Cancellation before the run starts must not leak into the next run; a second run on the same handle works.
        Native.runCancel(h);
        String res2;
        try (FileInputStream apk = new FileInputStream(fixtures + "/sample_multi_abi.apk")) {
            res2 = Native.run(h, req, fdOf(apk), -1, -1, null);
        }
        check(res2.contains("\"status_id\":\"success\""), "handle is reusable after cancel() and works without a listener");
        Native.runDelete(h);

        String badreq = Native.run(Native.runNew(), "{bad", -1, -1, -1, null);
        check(badreq.contains("\"ok\":false"), "malformed request yields a JSON error, not a crash");
        System.out.println(failures == 0 ? "ALL OK" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
