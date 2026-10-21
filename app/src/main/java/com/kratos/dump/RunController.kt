package com.kratos.dump

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs one analysis: native analysis into a private staging folder, then a verified copy into the folder the user picked.
 * The final status is never better than what reached the chosen folder.
 */
object RunController {
    private val exec = Executors.newSingleThreadExecutor()

    @Volatile
    private var handle = 0L
    private val cancelExport = AtomicBoolean(false)

    fun start(ctx: Context): Boolean {
        if (Session.busy) return false
        val problems = Session.blockers()
        if (problems.isNotEmpty()) {
            Session.lastMessage = "Запуск невозможен:\n• " + problems.joinToString("\n• ")
            Session.changed()
            return false
        }
        val app = ctx.applicationContext
        Session.state = RunState.Running
        Session.progressStage = ""
        Session.progressDone = 0
        Session.progressTotal = 0
        Session.progressText = "подготовка"
        Session.lastResult = null
        cancelExport.set(false)
        Session.changed()
        exec.execute {
            try {
                runInternal(app)
            } catch (t: Throwable) {
                Session.log(4, "app", "внутренняя ошибка запуска: ${t.javaClass.simpleName}: ${t.message}")
                Session.lastMessage = "Запуск прерван внутренней ошибкой: ${t.message ?: t.javaClass.simpleName}"
            } finally {
                if (Session.state != RunState.Done) Session.state = RunState.Idle
                AnalysisService.stop(app)
                Session.changed()
            }
        }
        return true
    }

    fun cancel() {
        when (Session.state) {
            RunState.Running -> {
                val h = handle
                if (h != 0L) Native.runCancel(h)
                Session.log(3, "app", "отмена запрошена пользователем")
            }
            RunState.Exporting -> {
                cancelExport.set(true)
                Session.log(3, "app", "отмена копирования запрошена пользователем")
            }
            else -> {}
        }
    }

    private fun fail(msg: String) {
        Session.log(4, "app", msg)
        Session.lastMessage = msg
        Session.state = RunState.Idle
    }

    private fun runInternal(app: Context) {
        val tree = Session.outTree ?: return fail("Запуск не начат: не выбрана папка результата")
        // Re-check just before the run: the folder may have been removed or the permission revoked since it was picked.
        val chk = Saf.checkTree(app, tree)
        if (!chk.ok) return fail("Запуск не начат: папка результата недоступна: ${chk.message}. Выберите другое расположение.")
        if (chk.freeBytes in 0 until (16L shl 20))
            return fail("Запуск не начат: в папке результата свободно только ${humanSize(chk.freeBytes)}. Освободите место или выберите другое расположение.")

        val runId = "run_" + System.currentTimeMillis()
        val staging = File(app.getExternalFilesDir("staging") ?: File(app.filesDir, "staging"), runId).also { it.mkdirs() }
        val tmp = File(app.cacheDir, "tmp/$runId").also { it.mkdirs() }
        val mode = Session.mode
        val inputName = Session.inputName()

        val fds = ArrayList<ParcelFileDescriptor>()
        fun open(f: PickedFile?): Int {
            if (f == null) return -1
            val p = Saf.openRead(app, f.uri) ?: return -2
            fds.add(p)
            return p.fd
        }
        val apkFd = if (mode == "apk") open(Session.apk) else -1
        val libFd = if (mode == "lib") open(Session.lib) else -1
        val wantMetaFile = Session.metaChoice == MetaChoice.File && Session.metaFile != null
        val metaFd = if (wantMetaFile) open(Session.metaFile) else -1
        if (apkFd == -2 || libFd == -2 || metaFd == -2) {
            fds.forEach { try { it.close() } catch (_: Exception) {} }
            staging.deleteRecursively()
            tmp.deleteRecursively()
            return fail("Запуск не начат: выбранный файл больше не открывается (доступ закрыт или файл удалён). Выберите его заново.")
        }

        val req = JSONObject()
            .put("mode", mode)
            .put("display_name", inputName)
            .put("lib_name", Session.lib?.name ?: "")
            .put("meta_name", if (wantMetaFile) Session.metaFile?.name ?: "" else "")
            .put("out_root", staging.absolutePath)
            .put("temp_dir", tmp.absolutePath)
            .put("profile", SettingsStore.profileId)
            .put("selected_libs", JSONArray(if (mode == "apk") Session.selectedLibs.toList() else emptyList<String>()))
            .put(
                "selected_meta",
                when (val c = Session.metaChoice) {
                    is MetaChoice.None -> "none"
                    is MetaChoice.Entry -> c.entry
                    else -> ""
                },
            )
            .put("config", SettingsStore.overridesCopy())

        val h = Native.runNew()
        handle = h
        AnalysisService.start(app)
        val wl = (app.getSystemService(Context.POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "kratos:run")
        try {
            wl.acquire(3 * 60 * 60 * 1000L)
        } catch (_: Exception) {
        }
        Session.log(1, "app", "запуск анализа: $inputName, профиль ${SettingsStore.profileId}")

        val listener = object : NativeListener {
            override fun onProgress(stage: String, done: Long, total: Long, text: String) {
                Session.progressStage = stage
                Session.progressDone = done
                Session.progressTotal = total
                Session.progressText = text
                Session.main.post { Session.changed() }
                AnalysisService.update(app, text.ifEmpty { stage }, done, total)
            }

            override fun onLog(tsMs: Long, level: Int, stage: String, msg: String) {
                Session.log(level, stage, msg, tsMs)
            }
        }
        val outcome: JSONObject
        try {
            outcome = parseJson(Native.run(h, req.toString(), apkFd, libFd, metaFd, listener))
        } finally {
            handle = 0
            Native.runDelete(h)
            fds.forEach { try { it.close() } catch (_: Exception) {} }
            try { if (wl.isHeld) wl.release() } catch (_: Exception) {}
            tmp.deleteRecursively()
        }

        val statusId = outcome.str("status_id", "error")
        val runDir = outcome.str("run_dir")
        if (!outcome.bool("ok", false) || runDir.isEmpty()) {
            staging.deleteRecursively()
            val why = outcome.str("error").ifEmpty { "причина не указана" }
            return fail("Анализ не запущен: $why")
        }

        // -------------------------------------------------------------- copy into the chosen folder
        Session.state = RunState.Exporting
        Session.progressText = "копирование результатов"
        Session.progressDone = 0
        Session.progressTotal = 0
        Session.changed()
        Session.log(1, "export", "копирование результатов в «${Session.outName}/android_dump»")
        val src = File(runDir)
        val ex = Saf.exportRun(app, src, tree, cancelExport) { done, total, file ->
            Session.progressDone = done.toLong()
            Session.progressTotal = total.toLong()
            Session.progressText = if (file.isEmpty()) "копирование завершено" else "копирование: $file"
            Session.main.post { Session.changed() }
        }
        val summary = outcome.obj("summary")
        var finalId = statusId
        var finalText = outcome.str("status_text")
        val failures = ArrayList(ex.failures)
        val exportJson = JSONObject()
            .put("destination", "${Session.outName}/android_dump/${ex.runName}")
            .put("files_total", ex.total)
            .put("files_copied", ex.copied)
            .put("bytes_copied", ex.bytes)
            .put("cancelled", ex.cancelled)
        if (ex.runDocId != null) {
            // summary.json goes last, once the outcome of the copy is known.
            if (!ex.complete) {
                if (ex.cancelled) {
                    finalId = "cancelled"
                    finalText = "Отменено пользователем"
                } else if (finalId == "success") {
                    finalId = "error"
                    finalText = "Завершено с ошибкой"
                }
                val st = summary.obj("status")
                st.put("id", finalId).put("text", finalText)
                val mf = st.optJSONArray("mandatory_failures") ?: JSONArray().also { st.put("mandatory_failures", it) }
                mf.put("сохранение результатов в выбранную папку")
                summary.put("status", st)
                val errs = summary.optJSONArray("errors") ?: JSONArray().also { summary.put("errors", it) }
                errs.put(
                    if (ex.cancelled) "копирование в выбранную папку отменено: сохранено ${ex.copied} из ${ex.total} файлов"
                    else "в выбранную папку сохранено ${ex.copied} из ${ex.total} файлов",
                )
            }
            exportJson.put("complete", ex.complete).put("failures", JSONArray(failures))
            summary.put("export", exportJson)
            val err = Saf.writeText(app, tree, ex.runDocId, "summary.json", summary.toString(2))
            if (err != null) {
                failures.add("summary.json: $err")
                if (finalId == "success") {
                    finalId = "error"
                    finalText = "Завершено с ошибкой"
                }
            }
        } else {
            if (finalId == "success") {
                finalId = "error"
                finalText = "Завершено с ошибкой"
            }
            exportJson.put("complete", false).put("failures", JSONArray(failures))
            summary.put("export", exportJson)
        }
        val exportOk = ex.complete && failures.isEmpty()
        failures.take(8).forEach { Session.log(4, "export", it) }
        if (failures.size > 8) Session.log(4, "export", "… и ещё ${failures.size - 8}")
        Session.log(
            if (exportOk) 2 else 4,
            "export",
            if (exportOk) "сохранено файлов: ${ex.copied}, ${humanSize(ex.bytes)}" else "результаты сохранены не полностью: ${ex.copied} из ${ex.total} файлов",
        )

        var note = ""
        if (exportOk) {
            staging.deleteRecursively()
        } else {
            note = "Часть результатов осталась во временной папке приложения: ${staging.absolutePath}"
            Session.log(3, "export", note)
        }

        val runDocUri = if (ex.runDocId != null) Saf.fileDocUri(tree, ex.runDocId).toString() else ""
        val det = HistoryEntry.details(summary)
        val hist = HistoryEntry(
            id = runId, tsMs = System.currentTimeMillis(), mode = mode, inputName = inputName, statusId = finalId, statusText = finalText,
            runName = ex.runName, treeUri = tree.toString(), runDocUri = runDocUri, exportOk = exportOk, note = note,
            profileTitle = det.profileTitle, archLabel = det.archLabel, hasMetadata = det.hasMetadata, durationMs = det.durationMs, filesCount = det.filesCount,
        )
        if (SettingsStore.bool("history.enabled")) Prefs.historyAdd(hist, summary.toString(), SettingsStore.int("history.max_entries", 100))
        Session.lastResult = RunResult(finalId, finalText, inputName, ex.runName, summary, exportOk, note, tree.toString(), runDocUri, if (exportOk) "" else staging.absolutePath, runId)
        Session.state = RunState.Done
        Session.log(if (finalId == "success") 2 else if (finalId == "cancelled") 3 else 4, "app", finalText)
        AnalysisService.notifyDone(app, "KRATOS DUMP: $finalText", inputName)
        Session.changed()
    }
}
