package com.kratos.dump

import android.app.AlertDialog
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView

class MainScreen(act: MainActivity) : Screen(act), SessionListener {
    private lateinit var content: LinearLayout
    private lateinit var console: ConsoleView
    private var seenSettingsVersion = SettingsStore.version

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)

        // top bar
        val bar = hbox(ctx, 14)
        val titleBox = vbox(ctx)
        titleBox.addView(label(ctx, "KRATOS DUMP", 19f, C.text, bold = true))
        titleBox.addView(label(ctx, "анализ APK и .so", 12f, C.muted))
        bar.addView(titleBox, lp(w = 0, weight = 1f))
        bar.addView(ghostButton(ctx, "История") { act.push(HistoryScreen(act)) })
        bar.addView(hspace(ctx, 6))
        bar.addView(ghostButton(ctx, "Настройки") { act.push(SettingsScreen(act)) })
        bar.addView(hspace(ctx, 6))
        bar.addView(ghostButton(ctx, "О приложении") { act.push(AboutScreen(act)) })
        root.addView(bar)
        root.addView(divider(ctx))

        content = vbox(ctx, 14)
        root.addView(scroll(ctx, content), lp(h = 0, weight = 1f))

        // mini console
        root.addView(divider(ctx))
        val head = hbox(ctx, 8)
        head.setBackgroundColor(C.panel)
        head.addView(label(ctx, "Журнал", 12f, C.muted, bold = true), lp(w = 0, weight = 1f))
        head.addView(label(ctx, "развернуть", 12f, C.accent).apply { setOnClickListener { act.push(ConsoleScreen(act)) } })
        root.addView(head)
        console = ConsoleView(ctx, 11f, 80)
        console.setBackgroundColor(C.panel)
        root.addView(console, lp(h = ctx.dp(130)))
        console.setOnClickListener { act.push(ConsoleScreen(act)) }
        refresh()
        return root
    }

    override fun onShow() {
        Session.addListener(this)
        if (::content.isInitialized) {
            // Settings may have changed in the meantime; the console follows them.
            console.reload()
            refresh()
            if (seenSettingsVersion != SettingsStore.version) {
                seenSettingsVersion = SettingsStore.version
                if (Session.mode == "apk") Session.reprobe()
            }
        }
    }

    override fun onHide() {
        Session.removeListener(this)
    }

    override fun onStateChanged() = refresh()

    // ------------------------------------------------------------------ content
    private fun tile(title: String, lines: List<Pair<String, Int>>, onClick: () -> Unit, onClear: (() -> Unit)? = null, mono: Boolean = false): View {
        val ctx = act
        val c = card(ctx, onClick)
        val head = hbox(ctx)
        head.addView(label(ctx, title.uppercase(), 11f, C.accent, bold = true), lp(w = 0, weight = 1f))
        if (onClear != null) head.addView(label(ctx, "убрать", 12f, C.muted).apply { setOnClickListener { onClear() }; setPadding(ctx.dp(8), 0, 0, 0) })
        c.addView(head)
        for ((i, l) in lines.withIndex()) {
            c.addView(space(ctx, if (i == 0) 6 else 3))
            val isPath = i > 0 && (l.first.startsWith("content://") || l.first.startsWith("file://") || l.first.startsWith("/storage/"))
            val t = label(ctx, l.first, if (i == 0) 15f else 12f, l.second, bold = i == 0, mono = isPath)
            if (isPath) {
                t.maxLines = 1
                t.ellipsize = TextUtils.TruncateAt.MIDDLE
            }
            c.addView(t)
        }
        return c
    }

    private fun refresh() {
        if (!::content.isInitialized) return
        val ctx = act
        content.removeAllViews()
        val gap = lp().apply { bottomMargin = ctx.dp(10) }

        // APK
        val apk = Session.apk
        val probe = Session.apkProbe
        if (apk == null) {
            content.addView(tile("APK", listOf("Не выбран" to C.text, "Нажмите, чтобы выбрать файл .apk" to C.muted), { act.pickApk() }), gap)
        } else {
            val lines = ArrayList<Pair<String, Int>>()
            lines.add(apk.name to C.text)
            when {
                Session.apkBusy -> lines.add("проверка архива…" to C.muted)
                probe == null -> {}
                probe.ok -> lines.add(
                    "Архив читается · записей ${probe.entries} · библиотек ${probe.libs.size} · метаданных ${probe.metas.size}" +
                        (if (probe.recovered) " · каталог восстановлен" else "") to if (probe.recovered) C.warn else C.ok,
                )
                else -> lines.add("Не читается: ${probe.error}" to C.err)
            }
            lines.add(humanSize(apk.size) to C.muted)
            lines.add(apk.uri.toString() to C.muted)
            content.addView(tile("APK", lines, { act.pickApk() }, { Session.clearApk() }, mono = true), gap)
        }

        // Library
        content.addView(libraryTile(), gap)

        // Metadata
        content.addView(metaTile(), gap)

        // Output
        content.addView(outputTile(), gap)

        content.addView(summaryCard(), gap)
        content.addView(runControls(), gap)
        content.addView(space(ctx, 6))
    }

    private fun libraryTile(): View {
        val lines = ArrayList<Pair<String, Int>>()
        val onClear: (() -> Unit)?
        val onClick: () -> Unit
        if (Session.apk != null) {
            val p = Session.apkProbe
            onClick = { showLibraryDialog(act) }
            onClear = null
            if (p == null) lines.add("Ожидание проверки APK…" to C.muted)
            else if (p.libs.isEmpty()) {
                lines.add("В APK нет нативных библиотек" to C.warn)
                lines.add("Нажмите, чтобы выбрать отдельный файл .so" to C.muted)
                return tile("Библиотека", lines, { act.pickLib() })
            } else {
                val sel = Session.libsForRun()
                lines.add((if (sel.isEmpty()) "Не выбрано" else if (sel.size == 1) sel[0].name else "Выбрано: ${sel.size}") to if (sel.isEmpty()) C.warn else C.text)
                lines.add("Найдено: ${p.libs.size} · ${if (Session.libsManual) "выбор изменён вручную" else "автоматический выбор"}" to C.muted)
                for (l in sel.take(4)) lines.add("${l.name}: ${l.description}" to if (l.isElf) C.muted else C.warn)
                if (sel.size > 4) lines.add("… и ещё ${sel.size - 4}" to C.muted)
                lines.add("Нажмите, чтобы посмотреть варианты и изменить выбор" to C.muted)
            }
        } else if (Session.lib != null) {
            val f = Session.lib!!
            val lp = Session.libProbe
            onClick = { act.pickLib() }
            onClear = { Session.clearLib() }
            lines.add(f.name to C.text)
            lines.add(humanSize(f.size) to C.muted)
            if (lp == null) lines.add("проверка…" to C.muted)
            else if (lp.isElf) lines.add("ELF · ${lp.description}" to C.ok)
            else lines.add("Не ELF: ${lp.note}" to C.warn)
            lines.add(f.uri.toString() to C.muted)
            return tile("Библиотека", lines, onClick, onClear, mono = true)
        } else {
            onClick = { act.pickLib() }
            onClear = null
            lines.add("Не выбрана" to C.text)
            lines.add("Нажмите, чтобы выбрать отдельный файл .so. Для APK библиотеки находятся автоматически." to C.muted)
        }
        return tile("Библиотека", lines, onClick, onClear)
    }

    private fun metaTile(): View {
        val lines = ArrayList<Pair<String, Int>>()
        val p = Session.apkProbe
        when (val c = Session.metaChoice) {
            is MetaChoice.Auto -> {
                if (Session.mode == "apk") {
                    val first = p?.metas?.firstOrNull()
                    if (p == null) lines.add("Автоматический поиск" to C.text)
                    else if (first != null) {
                        lines.add("Автоматически: ${first.name}" to C.text)
                        lines.add("${first.handler} · ${humanSize(first.size)}" + (if (p.metas.size > 1) " · вариантов: ${p.metas.size}" else "") to C.muted)
                    } else lines.add("Автоматически: ничего не найдено" to C.warn)
                } else lines.add("Не выбраны (необязательно)" to C.text)
            }
            is MetaChoice.None -> lines.add("Без метаданных" to C.text)
            is MetaChoice.Entry -> {
                lines.add("Из APK: ${c.entry.substringAfterLast('/')}" to C.text)
                lines.add(c.entry to C.muted)
            }
            is MetaChoice.File -> {
                val f = Session.metaFile
                lines.add((f?.name ?: "файл") to C.text)
                lines.add((f?.let { humanSize(it.size) } ?: "") to C.muted)
                val pr = Session.metaFileProbe
                if (pr == null) lines.add("проверка…" to C.muted)
                else if (pr.bool("recognized")) lines.add("Формат распознан: ${pr.str("handler")}, версия ${pr.optInt("version")}" to C.ok)
                else lines.add("Формат не распознан: ${pr.arr("problems").optString(0)}" to C.warn)
            }
        }
        lines.add("Нажмите, чтобы изменить" to C.muted)
        return tile("Метаданные", lines, { showMetaDialog(act) })
    }

    private fun outputTile(): View {
        val lines = ArrayList<Pair<String, Int>>()
        val t = Session.outTree
        if (t == null) {
            lines.add("Не выбрана" to C.text)
            lines.add("Нажмите, чтобы выбрать папку. Внутри будет создан каталог android_dump." to C.muted)
        } else {
            lines.add(Session.outName.ifEmpty { "папка" } to C.text)
            lines.add(Session.outHint to C.muted)
            val c = Session.outCheck
            if (c == null) lines.add("проверка записи…" to C.muted)
            else if (c.ok) lines.add("Запись возможна" + (if (c.freeBytes >= 0) " · свободно ${humanSize(c.freeBytes)}" else " · свободное место неизвестно") to C.ok)
            else lines.add(c.message to C.err)
        }
        return tile("Папка результата", lines, { act.pickOutput() })
    }

    private fun summaryCard(): View {
        val ctx = act
        val c = card(ctx)
        c.addView(label(ctx, "СВОДКА", 11f, C.accent, bold = true))
        c.addView(space(ctx, 8))
        fun row(k: String, v: String, color: Int = C.text, click: (() -> Unit)? = null) {
            val r = hbox(ctx)
            r.addView(label(ctx, k, 13f, C.muted), lp(w = ctx.dp(96)))
            val vv = label(ctx, v, 13f, color)
            r.addView(vv, lp(w = 0, weight = 1f))
            if (click != null) {
                r.isClickable = true
                r.setOnClickListener { click() }
            }
            c.addView(r, lp().apply { bottomMargin = ctx.dp(5) })
        }
        val mode = Session.mode
        row("Режим", when (mode) { "apk" -> "анализ APK"; "lib" -> "анализ отдельной библиотеки"; else -> "—" })
        row("Вход", Session.inputName().ifEmpty { "—" })
        if (mode == "apk") {
            val sel = Session.libsForRun()
            row("Библиотеки", if (sel.isEmpty()) "—" else sel.joinToString("\n") { "${it.name} (${it.abi.ifEmpty { it.arch }})" })
        }
        val changed = SettingsStore.changedKeys().size
        val p = SettingsStore.profile(SettingsStore.profileId)
        row("Профиль", (p?.title ?: SettingsStore.profileId) + (if (changed > 0) " · изменено: $changed" else ""), C.accent) {
            showProfileDialog(act) { refresh() }
        }
        row("Результат", if (Session.outTree != null && mode.isNotEmpty()) "${Session.outName}/android_dump/${runNameHint()}" else "—")
        for (r in Session.remarks()) {
            c.addView(label(ctx, "• $r", 12f, C.warn), lp().apply { topMargin = ctx.dp(4) })
        }
        return c
    }

    private fun runNameHint(): String {
        val base = Session.inputName().substringBeforeLast('.').ifEmpty { Session.inputName() }
        return "${base}_ГГГГММДД_ЧЧММСС"
    }

    private fun runControls(): View {
        val ctx = act
        val col = vbox(ctx)
        val st = Session.state
        if (st == RunState.Running || st == RunState.Exporting) {
            val c = card(ctx)
            c.addView(label(ctx, if (st == RunState.Running) "Анализ выполняется" else "Копирование результатов", 14f, C.text, bold = true))
            c.addView(space(ctx, 8))
            val pb = ProgressBar(ctx, null, android.R.attr.progressBarStyleHorizontal)
            pb.max = 1000
            if (Session.progressTotal > 0) {
                pb.isIndeterminate = false
                pb.progress = (Session.progressDone * 1000 / Session.progressTotal).toInt().coerceIn(0, 1000)
            } else pb.isIndeterminate = true
            pb.progressTintList = android.content.res.ColorStateList.valueOf(C.accent)
            pb.indeterminateTintList = android.content.res.ColorStateList.valueOf(C.accent)
            c.addView(pb, lp(h = ctx.dp(10)))
            c.addView(space(ctx, 8))
            val txt = label(ctx, listOf(Session.progressStage, Session.progressText).filter { it.isNotEmpty() }.joinToString(" · ").ifEmpty { "…" }, 12f, C.muted)
            txt.maxLines = 2
            txt.ellipsize = TextUtils.TruncateAt.END
            c.addView(txt)
            c.addView(space(ctx, 10))
            c.addView(ghostButton(ctx, "Отменить") {
                AlertDialog.Builder(act).setMessage("Остановить анализ? Уже созданные корректные результаты будут сохранены со статусом «Отменено пользователем».")
                    .setPositiveButton("Остановить") { _, _ -> RunController.cancel() }.setNegativeButton("Продолжить", null).show()
            })
            col.addView(c)
            return col
        }
        val blockers = Session.blockers()
        val btn = primaryButton(ctx, "Запустить анализ") {
            if (!RunController.start(act)) { /* the reason is shown by the session listener */ }
        }
        btn.isEnabled = blockers.isEmpty()
        btn.alpha = if (blockers.isEmpty()) 1f else 0.4f
        col.addView(btn, lp())
        if (blockers.isNotEmpty()) {
            col.addView(space(ctx, 8))
            col.addView(label(ctx, "Чтобы начать: " + blockers.joinToString("; "), 12f, C.muted))
        }
        val last = Session.lastResult
        if (last != null && st == RunState.Done) {
            col.addView(space(ctx, 10))
            val c = card(ctx) {
                act.push(ResultScreen(act, last.summary, last.statusId, last.statusText, last.inputName, last.runName, last.runDocUri, last.exportOk, last.exportNote))
            }
            c.addView(label(ctx, "Последний запуск: ${last.statusText}", 13f, statusColor(last.statusId), bold = true))
            c.addView(label(ctx, "${last.inputName} · нажмите, чтобы открыть результаты", 12f, C.muted))
            col.addView(c)
        }
        return col
    }
}
