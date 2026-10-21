package com.kratos.dump

import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.view.View
import android.widget.LinearLayout
import org.json.JSONObject

/** Result of one run, built from summary.json. The status shown is the one that reached the chosen folder. */
class ResultScreen(
    act: MainActivity,
    private val summary: JSONObject,
    private val statusId: String,
    private val statusText: String,
    private val inputName: String,
    private val runName: String,
    private val runDocUri: String,
    private val exportOk: Boolean,
    private val exportNote: String,
) : Screen(act) {
    override val title = "Результаты"

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, "Результаты", 18f, C.text, bold = true), lp(w = 0, weight = 1f))
        root.addView(bar)
        root.addView(divider(ctx))
        val col = vbox(ctx, 14)
        root.addView(scroll(ctx, col), lp(h = 0, weight = 1f))
        val gap = lp().apply { bottomMargin = ctx.dp(10) }

        // status
        val st = card(ctx)
        st.addView(label(ctx, statusText.ifEmpty { "—" }, 20f, statusColor(statusId), bold = true))
        st.addView(space(ctx, 6))
        st.addView(label(ctx, inputName, 14f, C.text))
        val run = summary.obj("run")
        val meta = listOf(
            "запуск $runName",
            run.str("profile_title").ifEmpty { run.str("profile") },
            run.lng("duration_ms").takeIf { it > 0 }?.let { "${it / 1000.0} с" } ?: "",
        ).filter { it.isNotEmpty() }
        st.addView(label(ctx, meta.joinToString(" · "), 12f, C.muted))
        if (!exportOk) {
            st.addView(space(ctx, 8))
            st.addView(label(ctx, "Результаты сохранены в выбранную папку не полностью или не подтверждены." + (if (exportNote.isNotEmpty()) "\n$exportNote" else ""), 12f, C.err))
        }
        val exp = summary.obj("export")
        if (exp.length() > 0) {
            st.addView(space(ctx, 6))
            st.addView(label(ctx, "Сохранено: ${exp.lng("files_copied")} из ${exp.lng("files_total")} файлов → ${exp.str("destination")}", 12f, C.muted))
        }
        val failed = summary.obj("status").arr("mandatory_failures")
        if (failed.length() > 0) {
            st.addView(space(ctx, 8))
            st.addView(label(ctx, "Обязательные этапы с ошибкой: " + (0 until failed.length()).joinToString("; ") { failed.optString(it) }, 12f, C.err))
        }
        val actions = hbox(ctx)
        if (runDocUri.isNotEmpty()) {
            actions.addView(ghostButton(ctx, "Открыть папку") { act.openFolder(runDocUri) })
            actions.addView(hspace(ctx, 8))
            actions.addView(ghostButton(ctx, "Файлы и отчёты") { openFiles() })
        }
        if (runDocUri.isNotEmpty()) {
            st.addView(space(ctx, 12))
            st.addView(actions)
        }
        col.addView(st, gap)

        // input
        val input = summary.obj("input")
        val apk = summary.obj("apk")
        val inp = card(ctx)
        inp.addView(label(ctx, "ВХОД", 11f, C.accent, bold = true))
        inp.addView(space(ctx, 6))
        inp.addView(kv("Файл", input.str("name") + " · " + humanSize(input.lng("size", -1))))
        if (input.str("sha256").isNotEmpty()) inp.addView(kv("SHA-256", input.str("sha256").take(16) + "…"))
        if (summary.str("mode").isNotEmpty() || run.str("mode").isNotEmpty()) inp.addView(kv("Режим", if (run.str("mode") == "apk") "APK" else "отдельная библиотека"))
        if (run.str("mode") == "apk") {
            if (apk.bool("readable")) {
                inp.addView(kv("Архив", "записей ${apk.lng("entries")}, распаковано ${humanSize(apk.lng("uncompressed_bytes"))}" + (if (apk.bool("central_directory_recovered")) ", каталог восстановлен" else "")))
                val abis = apk.arr("abis")
                if (abis.length() > 0) inp.addView(kv("ABI", (0 until abis.length()).joinToString(", ") { abis.optString(it) }))
                inp.addView(kv("Библиотек", "${apk.arr("library_candidates").length()}"))
            } else inp.addView(label(ctx, "Архив не читается: ${apk.str("error")}", 13f, C.err))
        }
        col.addView(inp, gap)

        // libraries
        val libs = summary.arr("libraries")
        libs.forEachObject { lib -> col.addView(libraryCard(lib), gap) }

        // metadata
        val md = summary.obj("metadata")
        if (md.bool("probed")) {
            val c = card(ctx)
            c.addView(label(ctx, "МЕТАДАННЫЕ", 11f, C.accent, bold = true))
            c.addView(space(ctx, 6))
            if (md.bool("found")) {
                c.addView(label(ctx, "${md.str("name")} · ${md.str("handler")} · ${md.str("status")}", 14f, if (md.str("status") == "ok") C.ok else C.warn, bold = true))
                val info = md.obj("info")
                if (info.has("version")) c.addView(kv("Версия", "${info.optInt("version")}" + if (info.bool("version_in_supported_range")) "" else " (вне поддерживаемого диапазона)"))
                val lit = info.obj("string_literals")
                if (lit.has("count")) c.addView(kv("Литералы", "${lit.lng("count")}"))
                val idn = info.obj("identifiers")
                if (idn.has("count")) c.addView(kv("Идентификаторы", "${idn.lng("count")}"))
                val pr = info.arr("problems")
                for (i in 0 until minOf(pr.length(), 4)) c.addView(label(ctx, "• ${pr.optString(i)}", 12f, C.warn))
            } else c.addView(label(ctx, "Метаданные не найдены.", 13f, C.muted))
            col.addView(c, gap)
        }

        // completeness
        col.addView(completenessCard(), gap)

        // problems
        val warns = summary.arr("warnings")
        val errs = summary.arr("errors")
        if (warns.length() + errs.length() > 0) {
            val c = card(ctx)
            c.addView(label(ctx, "ПРЕДУПРЕЖДЕНИЯ И ОШИБКИ", 11f, C.accent, bold = true))
            c.addView(space(ctx, 6))
            for (i in 0 until minOf(errs.length(), 12)) c.addView(label(ctx, "✕ ${errs.optString(i)}", 12f, C.err).apply { setPadding(0, 0, 0, ctx.dp(3)) })
            for (i in 0 until minOf(warns.length(), 12)) c.addView(label(ctx, "! ${warns.optString(i)}", 12f, C.warn).apply { setPadding(0, 0, 0, ctx.dp(3)) })
            val more = errs.length() + warns.length() - minOf(errs.length(), 12) - minOf(warns.length(), 12)
            if (more > 0) c.addView(label(ctx, "… ещё $more; полный список в logs/diagnostics.txt и reports/completeness.txt", 12f, C.muted))
            col.addView(c, gap)
        }

        // stages: the body is built once and toggled in place so the scroll position stays
        val stages = summary.arr("stages")
        val body = vbox(ctx).apply { visibility = View.GONE }
        val head = label(ctx, "ЭТАПЫ (${stages.length()}) ▸", 11f, C.accent, bold = true)
        val sc = card(ctx) {
            val open = body.visibility != View.VISIBLE
            body.visibility = if (open) View.VISIBLE else View.GONE
            head.text = "ЭТАПЫ (${stages.length()}) ${if (open) "▾" else "▸"}"
        }
        sc.addView(head)
        body.addView(space(ctx, 8))
        stages.forEachObject { s ->
            val lib = s.str("library")
            val line = "${s.str("title")}${if (lib.isNotEmpty()) " [$lib]" else ""} — ${statusRu(s.str("status"))}${if (s.lng("ms") > 0) ", ${s.lng("ms")} мс" else ""}"
            body.addView(label(ctx, line, 12f, stageColor(s.str("status"))).apply { setPadding(0, 0, 0, ctx.dp(2)) })
            val reason = s.str("reason")
            if (reason.isNotEmpty()) body.addView(label(ctx, "    $reason", 11f, C.muted).apply { setPadding(0, 0, 0, ctx.dp(4)) })
        }
        sc.addView(body)
        col.addView(sc, gap)
        col.addView(space(ctx, 16))
        return root
    }

    /** runDocUri is a document inside the chosen tree; the tree URI is rebuilt from it. */
    private fun openFiles() {
        val doc = Uri.parse(runDocUri)
        val auth = doc.authority
        if (auth == null) {
            act.toast("Папка результатов недоступна")
            return
        }
        val tree = DocumentsContract.buildTreeDocumentUri(auth, DocumentsContract.getTreeDocumentId(doc))
        act.push(FilesScreen(act, tree, DocumentsContract.getDocumentId(doc), runName))
    }

    private fun kv(k: String, v: String): View {
        val ctx = act
        val r = hbox(ctx)
        r.addView(label(ctx, k, 13f, C.muted), lp(w = ctx.dp(104)))
        r.addView(label(ctx, v, 13f, C.text), lp(w = 0, weight = 1f))
        r.layoutParams = lp().apply { bottomMargin = ctx.dp(4) }
        return r
    }

    private fun libraryCard(lib: JSONObject): View {
        val ctx = act
        val c = card(ctx)
        val elf = lib.obj("elf")
        c.addView(label(ctx, "БИБЛИОТЕКА", 11f, C.accent, bold = true))
        c.addView(space(ctx, 6))
        c.addView(label(ctx, lib.str("display").ifEmpty { lib.str("entry") }, 15f, C.text, bold = true))
        if (elf.bool("parsed")) {
            c.addView(label(ctx, "${elf.str("architecture")} · ${elf.optInt("bits")}-бит · ${if (elf.bool("little_endian", true)) "LE" else "BE"} · ${elf.str("type")} · ${humanSize(lib.lng("size"))}", 12f, C.muted))
        } else {
            c.addView(label(ctx, "ELF не разобран" + (if (elf.str("error").isNotEmpty()) ": ${elf.str("error")}" else ""), 12f, C.err))
        }
        c.addView(space(ctx, 8))
        if (elf.bool("parsed")) {
            c.addView(kv("Сегменты/секции", "${elf.lng("segments")} / ${elf.lng("sections")}" + (if (elf.bool("sections_reconstructed")) " (секции восстановлены)" else "")))
            c.addView(kv("Символы", "dynsym ${elf.lng("dynsym_parsed")}/${elf.lng("dynsym_declared")}, symtab ${elf.lng("symtab_parsed")}/${elf.lng("symtab_declared")}" + (if (elf.bool("symbols_partial")) " · неполно" else "")))
            c.addView(kv("Релокации", "${elf.lng("relocations")}" + (if (elf.bool("relocations_partial")) " · неполно" else "")))
            if (elf.lng("anomalies") > 0) c.addView(kv("Аномалии", "${elf.lng("anomalies")}"))
        }
        val fn = lib.obj("functions")
        if (fn.bool("ran")) {
            val conf = fn.obj("confidence")
            c.addView(kv("Функции", "${fn.lng("total")} (подтверждено структурой ${fn.lng("confirmed_by_structure")}, по анализу кода ${fn.lng("inferred_by_code_analysis")}); достоверность выс/сред/низ ${conf.lng("high")}/${conf.lng("medium")}/${conf.lng("low")}"))
            if (fn.lng("generated_names") > 0) c.addView(kv("Имена sub_*", "${fn.lng("generated_names")} сгенерировано"))
        }
        val s = lib.obj("strings")
        if (s.bool("ran")) c.addView(kv("Строки", "${s.lng("found")} найдено, записано ${s.lng("written")}" + (if (s.bool("truncated")) " · обрезано лимитом" else "")))
        val x = lib.obj("xrefs")
        if (x.has("total") && x.lng("total") > 0) c.addView(kv("Ссылки", "${x.lng("total")} (подтверждено ${x.lng("confirmed")}, предположительно ${x.lng("heuristic")})" + (if (x.bool("partial")) " · неполно" else "")))
        val cs = lib.obj("code_scan")
        if (cs.bool("ran")) c.addView(kv("Код", "${cs.lng("instructions")} инструкций, декодировано ${humanSize(cs.lng("bytes_decoded"))} из ${humanSize(cs.lng("bytes_total"))}" + (if (cs.lng("undecodable_runs") > 0) ", неразобранных участков ${cs.lng("undecodable_runs")}" else "")))
        val pr = lib.obj("protection")
        if (pr.bool("ran")) {
            val n = pr.arr("indicators").length()
            c.addView(kv("Защита", if (n == 0) "признаков упаковки и обфускации не найдено" else "признаков: $n (энтропия файла ${String.format(java.util.Locale.US, "%.2f", pr.optDouble("file_entropy"))})", ))
        }
        c.addView(label(ctx, "Статические оценки: «подтверждено» читается из структуры файла, «предположительно» выведено анализом кода.", 11f, C.muted).apply { setPadding(0, ctx.dp(6), 0, 0) })
        return c
    }

    private fun completenessCard(): View {
        val ctx = act
        val comp = summary.obj("completeness")
        val c = card(ctx)
        c.addView(label(ctx, "ПОЛНОТА АНАЛИЗА", 11f, C.accent, bold = true))
        c.addView(space(ctx, 6))
        val stages = comp.obj("stages")
        val parts = ArrayList<String>()
        for (k in stages.keys()) parts.add("${statusRu(k)}: ${stages.optInt(k)}")
        c.addView(kv("Этапы", parts.joinToString(", ").ifEmpty { "—" }))
        val files = comp.obj("files")
        c.addView(kv("Файлы", "создано ${files.lng("created")}, обрезано лимитом ${files.lng("cut_by_limit")}, не создано ${files.lng("failed")}"))
        val gaps = comp.arr("gaps")
        if (gaps.length() == 0) {
            c.addView(label(ctx, "Пробелов в анализе не зафиксировано. Это не доказывает, что файл разобран полностью: учитывайте ограничения статического анализа.", 12f, C.muted))
        } else {
            c.addView(label(ctx, "Пробелы (${gaps.length()}):", 12f, C.warn, bold = true).apply { setPadding(0, ctx.dp(4), 0, ctx.dp(4)) })
            for (i in 0 until minOf(gaps.length(), 15)) {
                val g = gaps.optJSONObject(i) ?: continue
                c.addView(label(ctx, "• ${gapKind(g.str("kind"))}: ${g.str("what")} — ${g.str("why")}", 12f, C.text).apply { setPadding(0, 0, 0, ctx.dp(3)) })
            }
            if (gaps.length() > 15) c.addView(label(ctx, "… ещё ${gaps.length() - 15}; полный список в reports/completeness.txt", 12f, C.muted))
        }
        return c
    }

    private fun gapKind(k: String) = when (k) {
        "unavailable" -> "недоступно"
        "skipped" -> "пропущено"
        "inferred" -> "выведено"
        "partial" -> "частично"
        else -> k
    }

    private fun statusRu(s: String) = when (s) {
        "ok" -> "выполнен"
        "partial" -> "частично"
        "failed" -> "ошибка"
        "skipped" -> "пропущен"
        "disabled" -> "отключён"
        "cancelled" -> "отменён"
        else -> s
    }

    private fun stageColor(s: String) = when (s) {
        "ok" -> C.text
        "partial", "cancelled" -> C.warn
        "failed" -> C.err
        else -> C.muted
    }
}

/** Browsing the folder of a finished run through the Storage Access Framework. */
class FilesScreen(act: MainActivity, private val tree: Uri, private val parentDocId: String, private val folderName: String) : Screen(act) {
    override val title = folderName

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, folderName, 17f, C.text, bold = true), lp(w = 0, weight = 1f))
        root.addView(bar)
        root.addView(divider(ctx))
        val col = vbox(ctx, 14)
        root.addView(scroll(ctx, col), lp(h = 0, weight = 1f))
        val loading = label(ctx, "Чтение папки…", 13f, C.muted)
        col.addView(loading)
        Thread {
            val kids = Saf.children(ctx, tree, parentDocId).sortedWith(compareBy({ !it.isDir }, { it.name }))
            Session.main.post {
                col.removeAllViews()
                if (kids.isEmpty()) col.addView(label(ctx, "Папка пуста или недоступна.", 13f, C.muted))
                for (k in kids) {
                    val c = card(ctx) {
                        if (k.isDir) act.push(FilesScreen(act, tree, k.docId, k.name))
                        else act.push(TextViewerScreen(act, Saf.fileDocUri(tree, k.docId), k.name, k.size))
                    }
                    c.addView(label(ctx, (if (k.isDir) "▸ " else "") + k.name, 14f, C.text))
                    if (!k.isDir) c.addView(label(ctx, humanSize(k.size), 11f, C.muted))
                    col.addView(c, lp().apply { bottomMargin = ctx.dp(8) })
                }
            }
        }.start()
        return root
    }
}

class TextViewerScreen(act: MainActivity, private val uri: Uri, private val name: String, private val size: Long) : Screen(act) {
    override val title = name
    private val limit = 768 * 1024

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, name, 16f, C.text, bold = true), lp(w = 0, weight = 1f))
        bar.addView(ghostButton(ctx, "Открыть в…") {
            val i = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "text/plain")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            try { act.startActivity(i) } catch (e: Exception) { act.toast("Нет приложения для просмотра файла") }
        })
        root.addView(bar)
        root.addView(divider(ctx))
        val tv = label(ctx, "Чтение…", 11f, C.text, mono = true).apply { setPadding(ctx.dp(12), ctx.dp(10), ctx.dp(12), ctx.dp(10)); setTextIsSelectable(true) }
        val h = android.widget.HorizontalScrollView(ctx).apply { addView(tv) }
        root.addView(scroll(ctx, h), lp(h = 0, weight = 1f))
        Thread {
            val r = Saf.readText(ctx, uri, limit)
            Session.main.post {
                if (r == null) tv.text = "Файл не прочитан."
                else tv.text = r.first + if (r.second) "\n\n… показано ${humanSize(limit.toLong())} из ${humanSize(size)}. Остальное смотрите кнопкой «Открыть в…»." else ""
            }
        }.start()
        return root
    }
}
