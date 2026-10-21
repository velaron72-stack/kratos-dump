package com.kratos.dump

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

class ConsoleLine(val tsMs: Long, val level: Int, val stage: String, val msg: String)

interface SessionListener {
    fun onStateChanged() {}
    fun onConsole(added: List<ConsoleLine>) {}
}

enum class RunState { Idle, Running, Exporting, Done }

/** Everything the screens of one run share: chosen files, probe results, run state, console. Lives as long as the process. */
object Session {
    private lateinit var app: Context
    val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val listeners = CopyOnWriteArrayList<SessionListener>()

    // ------------------------------------------------------------------ selection
    var apk: PickedFile? = null
        private set
    var apkProbe: ApkProbe? = null
        private set
    var apkBusy = false
        private set
    var lib: PickedFile? = null
        private set
    var libProbe: LibInfo? = null
        private set
    var metaFile: PickedFile? = null
        private set
    var metaFileProbe: JSONObject? = null
        private set
    var metaChoice: MetaChoice = MetaChoice.Auto
    val selectedLibs = LinkedHashSet<String>()
    var outTree: Uri? = null
        private set
    var outCheck: Saf.TreeCheck? = null
        private set
    var outName: String = ""
        private set
    var outHint: String = ""
        private set

    // ------------------------------------------------------------------ run state
    @Volatile
    var state = RunState.Idle
    var progressStage = ""
    var progressDone = 0L
    var progressTotal = 0L
    var progressText = ""
    var lastResult: RunResult? = null
    var lastMessage: String? = null  // shown once as a dialog by the main screen

    // ------------------------------------------------------------------ console
    private val console = ArrayList<ConsoleLine>()
    private val pending = ArrayList<ConsoleLine>()
    private var flushScheduled = false

    fun init(ctx: Context) {
        if (::app.isInitialized) return
        app = ctx.applicationContext
        Prefs.init(app)
        val t = Prefs.outTreeUri
        if (t.isNotEmpty()) {
            outTree = Uri.parse(t)
            refreshOutput()
        }
    }

    val appContext: Context get() = app

    fun addListener(l: SessionListener) {
        listeners.addIfAbsent(l)
    }

    fun removeListener(l: SessionListener) {
        listeners.remove(l)
    }

    fun changed() {
        if (Looper.myLooper() == Looper.getMainLooper()) listeners.forEach { it.onStateChanged() }
        else main.post { listeners.forEach { it.onStateChanged() } }
    }

    val mode: String get() = if (apk != null) "apk" else if (lib != null) "lib" else ""
    val busy: Boolean get() = state == RunState.Running || state == RunState.Exporting

    // ------------------------------------------------------------------ console
    fun log(level: Int, stage: String, msg: String, ts: Long = System.currentTimeMillis()) {
        val line = ConsoleLine(ts, level, stage, msg)
        synchronized(pending) {
            pending.add(line)
            if (!flushScheduled) {
                flushScheduled = true
                main.postDelayed({ flush() }, 80)
            }
        }
    }

    private fun flush() {
        val batch: List<ConsoleLine>
        synchronized(pending) {
            batch = ArrayList(pending)
            pending.clear()
            flushScheduled = false
        }
        val cap = SettingsStore.int("console.max_lines", 2000).coerceAtLeast(100)
        console.addAll(batch)
        if (console.size > cap) console.subList(0, console.size - cap).clear()
        listeners.forEach { it.onConsole(batch) }
    }

    fun consoleSnapshot(): List<ConsoleLine> = ArrayList(console)

    fun clearConsole() {
        console.clear()
        changed()
    }

    // ------------------------------------------------------------------ choosing files
    private fun probeTemp(): String = File(app.cacheDir, "probe").also { it.mkdirs() }.absolutePath

    var libsManual = false
        private set

    fun chooseApk(uri: Uri) {
        Saf.keepRead(app, uri)
        val f = Saf.queryFile(app, uri)
        apk = f
        lib = null
        libProbe = null
        selectedLibs.clear()
        libsManual = false
        metaChoice = MetaChoice.Auto
        log(1, "app", "выбран APK: ${f.name} (${humanSize(f.size)})")
        startApkProbe(uri, f, false)
    }

    /** Re-reads the archive, for example after the settings changed the automatic choice. A manual library choice is kept. */
    fun reprobe() {
        val f = apk ?: return
        if (apkBusy) return
        startApkProbe(f.uri, f, true)
    }

    private fun startApkProbe(uri: Uri, f: PickedFile, keepManual: Boolean) {
        apkProbe = null
        apkBusy = true
        changed()
        val profile = SettingsStore.profileId
        val overrides = SettingsStore.overridesForRun()
        worker.execute {
            val pfd = Saf.openRead(app, uri)
            val probe = if (pfd == null) {
                ApkProbe(JSONObject().put("ok", false).put("error", "файл не открывается: доступ закрыт или файл удалён"))
            } else {
                pfd.use { ApkProbe(parseJson(Native.probeApk(it.fd, f.name, profile, overrides, probeTemp()))) }
            }
            main.post {
                if (apk?.uri != uri) return@post  // another file was chosen meanwhile
                apkProbe = probe
                apkBusy = false
                if (keepManual && libsManual) {
                    val existing = probe.libs.map { it.entry }.toSet()
                    selectedLibs.retainAll(existing)
                } else {
                    selectedLibs.clear()
                    probe.libs.filter { it.selectedAuto }.forEach { selectedLibs.add(it.entry) }
                    libsManual = false
                }
                if (probe.ok) {
                    log(2, "app", "в архиве: записей ${probe.entries}, библиотек ${probe.libs.size}, метаданных ${probe.metas.size}, ABI: ${probe.abis.joinToString().ifEmpty { "нет" }}")
                } else {
                    log(4, "app", "архив не читается: ${probe.error}")
                }
                probe.warnings.forEach { log(3, "app", it) }
                changed()
            }
        }
    }

    fun setLibSelection(entries: Set<String>) {
        selectedLibs.clear()
        selectedLibs.addAll(entries)
        libsManual = true
        changed()
    }

    fun resetLibSelection() {
        val p = apkProbe ?: return
        selectedLibs.clear()
        p.libs.filter { it.selectedAuto }.forEach { selectedLibs.add(it.entry) }
        libsManual = false
        changed()
    }

    fun chooseLib(uri: Uri) {
        Saf.keepRead(app, uri)
        val f = Saf.queryFile(app, uri)
        lib = f
        libProbe = null
        apk = null
        apkProbe = null
        selectedLibs.clear()
        if (metaChoice != MetaChoice.File) metaChoice = MetaChoice.Auto
        log(1, "app", "выбрана библиотека: ${f.name} (${humanSize(f.size)})")
        changed()
        worker.execute {
            val pfd = Saf.openRead(app, uri)
            val info = if (pfd == null) null else pfd.use { LibProbeResult(parseJson(Native.probeLib(it.fd, f.name))) }
            main.post {
                if (lib?.uri != uri) return@post
                libProbe = info?.lib
                if (info == null) log(4, "app", "файл не открывается")
                else if (!info.lib.isElf) log(3, "app", "${f.name}: не ELF (${info.lib.note}); анализ всё равно будет выполнен в доступном объёме")
                else log(2, "app", "${f.name}: ${info.lib.description}")
                changed()
            }
        }
    }

    private class LibProbeResult(o: JSONObject) {
        val lib = LibInfo.from(o)
    }

    fun chooseMetaFile(uri: Uri) {
        Saf.keepRead(app, uri)
        val f = Saf.queryFile(app, uri)
        metaFile = f
        metaFileProbe = null
        metaChoice = MetaChoice.File
        log(1, "app", "выбран файл метаданных: ${f.name} (${humanSize(f.size)})")
        changed()
        worker.execute {
            val pfd = Saf.openRead(app, uri)
            val probe = if (pfd == null) null else pfd.use { parseJson(Native.probeMeta(it.fd, f.name)) }
            main.post {
                if (metaFile?.uri != uri) return@post
                metaFileProbe = probe
                if (probe == null) log(4, "app", "файл метаданных не открывается")
                else if (probe.bool("recognized")) log(2, "app", "метаданные распознаны: ${probe.str("handler")}, версия ${probe.optInt("version")}")
                else log(3, "app", "формат метаданных не распознан: ${probe.arr("problems").optString(0)}")
                changed()
            }
        }
    }

    fun clearApk() {
        apk = null
        apkProbe = null
        apkBusy = false
        selectedLibs.clear()
        if (metaChoice is MetaChoice.Entry) metaChoice = MetaChoice.Auto
        changed()
    }

    fun clearLib() {
        lib = null
        libProbe = null
        changed()
    }

    fun clearMetaFile() {
        metaFile = null
        metaFileProbe = null
        if (metaChoice == MetaChoice.File) metaChoice = MetaChoice.Auto
        changed()
    }

    fun chooseOutput(uri: Uri) {
        Saf.keepTree(app, uri)
        outTree = uri
        Prefs.outTreeUri = uri.toString()
        refreshOutput()
    }

    /** Re-reads the name and re-tests writability of the output folder. */
    fun refreshOutput() {
        val t = outTree ?: return
        outCheck = null
        outName = Saf.treeName(app, t)
        outHint = Saf.treePathHint(t)
        changed()
        worker.execute {
            val c = Saf.checkTree(app, t)
            main.post {
                if (outTree != t) return@post
                outCheck = c
                if (c.ok) log(2, "app", "папка результата: $outName: ${c.message}" + (if (c.freeBytes >= 0) ", свободно ${humanSize(c.freeBytes)}" else ", свободное место неизвестно"))
                else log(4, "app", "папка результата: ${c.message}")
                changed()
            }
        }
    }

    // ------------------------------------------------------------------ what a run would do
    /** A line for each reason that prevents starting; empty when a run can start. */
    fun blockers(): List<String> {
        val out = ArrayList<String>()
        if (!Native.ensureLoaded()) out.add("не загружена библиотека анализа: ${Native.loadError ?: "причина неизвестна"}")
        if (mode.isEmpty()) out.add("не выбран APK или библиотека")
        if (apkBusy) out.add("проверяется APK")
        if (outTree == null) out.add("не выбрана папка результата")
        else if (outCheck == null) out.add("проверяется папка результата")
        else if (outCheck?.ok == false) out.add("папка результата недоступна: ${outCheck?.message}")
        if (mode == "apk" && apkProbe != null && apkProbe?.ok == true && selectedLibs.isEmpty() && apkProbe?.libs?.isNotEmpty() == true)
            out.add("не выбрана ни одна библиотека")
        return out
    }

    /** Non-blocking remarks shown in the summary. */
    fun remarks(): List<String> {
        val out = ArrayList<String>()
        val p = apkProbe
        if (mode == "apk" && p != null) {
            if (!p.ok) out.add("APK не читается как архив (${p.error}): анализ завершится ошибкой, но отчёты о причине будут созданы")
            else if (p.libs.isEmpty()) out.add("в APK не найдено нативных библиотек: будет проанализирована только структура архива")
            if (p.recovered) out.add("каталог архива повреждён: записи восстановлены сканированием")
            p.libs.filter { it.entry in selectedLibs && !it.isElf }.forEach { out.add("${it.name}: не ELF") }
        }
        val l = libProbe
        if (mode == "lib" && l != null && !l.isElf) out.add("файл не похож на ELF: ${l.note}")
        if (metaChoice == MetaChoice.File) {
            val m = metaFileProbe
            if (m != null && !m.bool("recognized")) out.add("файл метаданных не распознан: он будет приложен, но разобран не будет")
        }
        return out
    }

    fun libsForRun(): List<LibInfo> = apkProbe?.libs?.filter { it.entry in selectedLibs } ?: emptyList()

    fun inputName(): String = apk?.name ?: lib?.name ?: ""
}

class RunResult(
    val statusId: String,
    val statusText: String,
    val inputName: String,
    val runName: String,
    val summary: JSONObject,
    val exportOk: Boolean,
    val exportNote: String,
    val treeUri: String,
    val runDocUri: String,
    val stagingPath: String,
    val liveHistoryId: String,
)
