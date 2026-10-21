package com.kratos.dump

import android.app.AlertDialog
import android.view.View
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** List of earlier runs. The result of a run is reopened from the summary kept inside the app. */
class HistoryScreen(act: MainActivity) : Screen(act) {
    override val title = "История"

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, "История запусков", 18f, C.text, bold = true), lp(w = 0, weight = 1f))
        root.addView(bar)
        root.addView(divider(ctx))
        val col = vbox(ctx, 14)
        root.addView(scroll(ctx, col), lp(h = 0, weight = 1f))
        val gap = lp().apply { bottomMargin = ctx.dp(10) }
        val fmt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault())

        val list = Prefs.historyList()
        if (!SettingsStore.bool("history.enabled")) {
            col.addView(label(ctx, "Запись истории выключена в настройках (history.enabled). Уже сохранённые записи ниже.", 12f, C.warn), gap)
        }
        if (list.isEmpty()) {
            col.addView(label(ctx, "Запусков пока нет.", 14f, C.muted), gap)
        }
        for (e in list.sortedByDescending { it.tsMs }) {
            val c = card(ctx) { openEntry(e) }
            c.addView(label(ctx, e.statusText.ifEmpty { e.statusId }, 15f, statusColor(e.statusId), bold = true))
            c.addView(label(ctx, e.inputName, 14f, C.text))
            c.addView(label(ctx, "${fmt.format(Date(e.tsMs))} · ${if (e.mode == "apk") "APK" else "библиотека"} · ${e.runName}", 11f, C.muted))
            val facts = listOfNotNull(
                e.profileTitle.ifEmpty { null },
                e.archLabel.ifEmpty { null },
                if (e.mode == "apk" || e.hasMetadata) (if (e.hasMetadata) "метаданные: есть" else "метаданные: нет") else null,
                if (e.durationMs > 0) "%.1f с".format(Locale.US, e.durationMs / 1000.0) else null,
                if (e.filesCount > 0) "файлов: ${e.filesCount}" else null,
            )
            if (facts.isNotEmpty()) c.addView(label(ctx, facts.joinToString(" · "), 11f, C.muted))
            if (!e.exportOk) c.addView(label(ctx, "Результаты сохранены не полностью" + (if (e.note.isNotEmpty()) ": ${e.note}" else ""), 11f, C.err))
            val row = hbox(ctx)
            if (e.runDocUri.isNotEmpty()) {
                row.addView(ghostButton(ctx, "Открыть папку") { act.openFolder(e.runDocUri) })
                row.addView(hspace(ctx, 8))
            }
            row.addView(ghostButton(ctx, "Удалить запись") { confirm("Удалить запись из истории? Файлы результатов в выбранной папке не затрагиваются.") { Prefs.historyRemove(e.id); act.refresh() } })
            c.addView(space(ctx, 10))
            c.addView(row)
            col.addView(c, gap)
        }

        if (list.isNotEmpty()) {
            col.addView(ghostButton(ctx, "Очистить историю") {
                confirm("Удалить все записи истории? Файлы результатов в выбранной папке не затрагиваются.") { Prefs.historyClear(); act.refresh() }
            }, gap)
        }
        val staged = stagingSize()
        col.addView(card(ctx).also { c ->
            c.addView(label(ctx, "ВРЕМЕННЫЕ ФАЙЛЫ", 11f, C.accent, bold = true))
            c.addView(space(ctx, 6))
            c.addView(label(ctx, "Анализ сначала пишется во временную папку приложения и затем копируется в выбранную папку. После успешной проверки копии временные файлы удаляются; остаются они только при неполном сохранении.", 12f, C.muted))
            c.addView(space(ctx, 8))
            c.addView(label(ctx, "Сейчас занято: ${humanSize(staged)}", 13f, C.text))
            if (staged > 0 && Session.state != RunState.Running) {
                c.addView(space(ctx, 8))
                c.addView(ghostButton(ctx, "Очистить временные файлы") {
                    confirm("Удалить временные файлы? Результаты, не попавшие в выбранную папку, будут потеряны.") { clearStaging(); act.refresh() }
                })
            } else if (staged > 0) {
                c.addView(label(ctx, "Очистка недоступна, пока идёт анализ.", 12f, C.muted))
            }
        }, gap)
        col.addView(space(ctx, 16))
        return root
    }

    private fun openEntry(e: HistoryEntry) {
        val text = Prefs.historySummary(e.id)
        if (text == null) {
            act.toast("Сводка этого запуска не сохранена в приложении. Откройте папку с результатами.")
            return
        }
        val summary = parseJson(text)
        act.push(ResultScreen(act, summary, e.statusId, e.statusText, e.inputName, e.runName, e.runDocUri, e.exportOk, e.note))
    }

    private fun confirm(msg: String, action: () -> Unit) {
        AlertDialog.Builder(act).setMessage(msg).setPositiveButton("Да") { _, _ -> action() }.setNegativeButton("Отмена", null).show()
    }

    private fun stagingRoot(): File? = Session.appContext.getExternalFilesDir("staging") ?: File(Session.appContext.filesDir, "staging")

    private fun stagingSize(): Long {
        val r = stagingRoot() ?: return 0
        var total = 0L
        r.walkTopDown().forEach { if (it.isFile) total += it.length() }
        return total
    }

    private fun clearStaging() {
        val r = stagingRoot() ?: return
        r.listFiles()?.forEach { it.deleteRecursively() }
    }
}

/** Version, libraries used, and what the program does not do. */
class AboutScreen(act: MainActivity) : Screen(act) {
    override val title = "О приложении"

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, "О приложении", 18f, C.text, bold = true), lp(w = 0, weight = 1f))
        root.addView(bar)
        root.addView(divider(ctx))
        val col = vbox(ctx, 14)
        root.addView(scroll(ctx, col), lp(h = 0, weight = 1f))
        val gap = lp().apply { bottomMargin = ctx.dp(10) }

        val info: JSONObject = if (Native.ensureLoaded()) parseJson(Native.info()) else JSONObject()
        val deps = info.obj("dependencies")

        col.addView(card(ctx).also { c ->
            c.addView(label(ctx, "KRATOS DUMP", 20f, C.text, bold = true))
            c.addView(label(ctx, "версия ${info.str("version", "—")}", 13f, C.muted))
            c.addView(space(ctx, 8))
            c.addView(label(ctx, "Статический анализ APK и нативных библиотек .so (ELF). Файлы читаются, ничего не запускается и не изменяется. Результаты строятся по тому, что удалось прочитать; пробелы и догадки отмечаются отдельно.", 13f, C.text))
            val arch = info.arr("architectures")
            if (arch.length() > 0) {
                c.addView(space(ctx, 6))
                c.addView(label(ctx, "Архитектуры: " + (0 until arch.length()).joinToString(", ") { arch.optString(it) }, 12f, C.muted))
            }
        }, gap)

        col.addView(card(ctx).also { c ->
            c.addView(label(ctx, "СТОРОННИЕ КОМПОНЕНТЫ", 11f, C.accent, bold = true))
            c.addView(space(ctx, 8))
            comp(c, "zlib", deps.str("zlib", "1.3.2"), "zlib License", "распаковка deflate в APK")
            comp(c, "Zstandard", deps.str("zstd", "1.5.7"), "BSD-3-Clause (двойная лицензия, выбрана BSD)", "ZIP-метод 93 (zstd)")
            comp(c, "Capstone", deps.str("capstone", "5.0.9"), "BSD-3-Clause", "дизассемблер ARM, ARM64, x86, x86-64")
            comp(c, "ELFIO", "3.12", "MIT", "второй независимый разбор ELF для сверки")
            c.addView(space(ctx, 6))
            c.addView(label(ctx, "LIEF и Unicorn не подключены: Unicorn распространяется под GPL-2.0, LIEF дублирует собственный разбор ELF и сильно увеличивает размер. Подробности в DEPENDENCIES.md.", 11f, C.muted))
            c.addView(space(ctx, 10))
            c.addView(ghostButton(ctx, "Тексты лицензий") { act.push(AssetTextScreen(act, "THIRD_PARTY_NOTICES.txt", "Лицензии")) })
        }, gap)

        col.addView(card(ctx).also { c ->
            c.addView(label(ctx, "ОГРАНИЧЕНИЯ", 11f, C.accent, bold = true))
            c.addView(space(ctx, 6))
            c.addView(label(ctx, "• Анализ статический: код не выполняется, поэтому упакованные и зашифрованные участки видны как данные.\n• Границы функций без символов определяются по признакам; такие функции помечены как предположительные.\n• Перекрёстные ссылки делятся на подтверждённые и эвристические.\n• Полнота каждого запуска описана в reports/completeness.txt.", 12f, C.text))
        }, gap)
        col.addView(space(ctx, 16))
        return root
    }

    private fun comp(c: android.widget.LinearLayout, name: String, version: String, license: String, use: String) {
        val ctx = act
        c.addView(label(ctx, "$name $version", 14f, C.text, bold = true))
        c.addView(label(ctx, "$license · $use", 12f, C.muted).apply { setPadding(0, 0, 0, ctx.dp(8)) })
    }
}

/** Shows a text file from the app assets (the license texts). */
class AssetTextScreen(act: MainActivity, private val asset: String, override val title: String) : Screen(act) {
    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, title, 17f, C.text, bold = true), lp(w = 0, weight = 1f))
        root.addView(bar)
        root.addView(divider(ctx))
        val text = try {
            ctx.assets.open(asset).use { String(it.readBytes(), Charsets.UTF_8) }
        } catch (e: Exception) {
            "Файл $asset не найден в приложении: ${e.message}"
        }
        val tv = label(ctx, text, 11f, C.text, mono = true).apply { setPadding(ctx.dp(12), ctx.dp(10), ctx.dp(12), ctx.dp(10)); setTextIsSelectable(true) }
        root.addView(scroll(ctx, tv), lp(h = 0, weight = 1f))
        return root
    }
}
