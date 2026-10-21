package com.kratos.dump

import android.app.AlertDialog
import android.content.res.ColorStateList
import android.view.View
import android.widget.CheckBox
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView

private fun tint(cb: android.widget.CompoundButton) {
    cb.buttonTintList = ColorStateList.valueOf(C.accent)
    cb.setTextColor(C.text)
}

private fun withScroll(act: MainActivity, content: View): View = ScrollView(act).apply { addView(content) }

/** Choice of the libraries to analyze among those found in the APK. */
fun showLibraryDialog(act: MainActivity) {
    val probe = Session.apkProbe
    if (probe == null) {
        act.toast("Архив ещё проверяется")
        return
    }
    val col = vbox(act, 16)
    col.addView(label(act, "Найдено библиотек: ${probe.libs.size}. Автоматический выбор: ${probe.libs.count { it.selectedAuto }}. Отметьте то, что нужно проанализировать.", 13f, C.muted))
    col.addView(space(act, 10))
    val boxes = ArrayList<Pair<CheckBox, LibInfo>>()
    if (probe.libs.isEmpty()) col.addView(label(act, "В архиве нет нативных библиотек.", 14f, C.warn))
    for (l in probe.libs.sortedBy { it.rank }) {
        val cb = CheckBox(act).apply {
            isChecked = l.entry in Session.selectedLibs
            text = buildString {
                append(l.name)
                if (l.selectedAuto) append("  · авто")
                append("\n").append(l.description)
                if (l.skippedByArch) append("\nпропущена настройкой «поддерживаемые архитектуры»")
                if (l.note.isNotEmpty()) append("\n").append(l.note)
                append("\n").append(l.entry)
            }
            textSize = 13f
        }
        tint(cb)
        boxes.add(cb to l)
        col.addView(cb)
        col.addView(space(act, 6))
    }
    AlertDialog.Builder(act)
        .setTitle("Библиотеки APK")
        .setView(withScroll(act, col))
        .setPositiveButton("Готово") { _, _ -> Session.setLibSelection(boxes.filter { it.first.isChecked }.map { it.second.entry }.toSet()) }
        .setNeutralButton("Автовыбор") { _, _ -> Session.resetLibSelection() }
        .setNegativeButton("Другой файл…") { _, _ -> act.pickLib() }
        .show()
}

/** Choice of the metadata source. */
fun showMetaDialog(act: MainActivity) {
    val col = vbox(act, 16)
    val group = RadioGroup(act)
    col.addView(group)
    data class Opt(val id: Int, val choice: MetaChoice?, val text: String)
    val opts = ArrayList<Opt>()
    val probe = Session.apkProbe
    var id = 1
    if (Session.mode == "apk") {
        val first = probe?.metas?.firstOrNull()
        opts.add(Opt(id++, MetaChoice.Auto, "Автоматически\n" + (if (first != null) "${first.name} (${first.handler}) — ${first.entry}" else "подходящих файлов не найдено")))
        opts.add(Opt(id++, MetaChoice.None, "Без метаданных\nанализ продолжится без них"))
        probe?.metas?.forEach { m ->
            opts.add(Opt(id++, MetaChoice.Entry(m.entry), "${m.name}\n${m.entry} · ${humanSize(m.size)}" + (if (m.note.isNotEmpty()) "\n${m.note}" else "")))
        }
    } else {
        opts.add(Opt(id++, MetaChoice.None, "Без метаданных\nметаданные необязательны"))
    }
    val file = Session.metaFile
    if (file != null) opts.add(Opt(id++, MetaChoice.File, "Файл: ${file.name}\n${humanSize(file.size)} · ${Session.metaFileProbe?.let { if (it.bool("recognized")) "формат распознан" else "формат не распознан" } ?: "проверяется"}"))
    val current = Session.metaChoice
    for (o in opts) {
        val rb = RadioButton(act).apply {
            this.id = o.id
            text = o.text
            textSize = 13f
            buttonTintList = ColorStateList.valueOf(C.accent)
            setTextColor(C.text)
            setPadding(0, act.dp(6), 0, act.dp(6))
            isChecked = o.choice == current || (o.choice is MetaChoice.Entry && current is MetaChoice.Entry && o.choice.entry == current.entry) ||
                (current == MetaChoice.Auto && Session.mode == "lib" && o.choice == MetaChoice.None && Session.metaFile == null)
        }
        group.addView(rb)
    }
    AlertDialog.Builder(act)
        .setTitle("Метаданные")
        .setView(withScroll(act, col))
        .setPositiveButton("Готово") { _, _ ->
            val sel = opts.firstOrNull { it.id == group.checkedRadioButtonId }?.choice
            if (sel != null) {
                Session.metaChoice = sel
                Session.changed()
            }
        }
        .setNeutralButton("Выбрать файл…") { _, _ -> act.pickMeta() }
        .also { if (Session.metaFile != null) it.setNegativeButton("Убрать файл") { _, _ -> Session.clearMetaFile() } else it.setNegativeButton("Отмена", null) }
        .show()
}

/** Quick profile choice from the main screen. */
fun showProfileDialog(act: MainActivity, after: () -> Unit) {
    val ids = SettingsStore.profiles.map { it.id }
    val labels = SettingsStore.profiles.map { "${it.title}\n${it.description}" }.toTypedArray()
    val cur = ids.indexOf(SettingsStore.profileId)
    AlertDialog.Builder(act)
        .setTitle("Профиль анализа")
        .setSingleChoiceItems(labels, cur) { d, which ->
            val id = ids[which]
            d.dismiss()
            if (id == SettingsStore.profileId) return@setSingleChoiceItems
            val apply = {
                SettingsStore.selectProfile(id)
                Session.reprobe()
                after()
            }
            if (SettingsStore.changedKeys().isNotEmpty())
                AlertDialog.Builder(act).setMessage("Выбор профиля сбросит отдельные изменённые параметры (${SettingsStore.changedKeys().size}). Продолжить?")
                    .setPositiveButton("Продолжить") { _, _ -> apply() }.setNegativeButton("Отмена", null).show()
            else apply()
        }
        .setNegativeButton("Закрыть", null)
        .show()
}

/** The ⓘ description of one setting. */
fun showSettingInfo(act: MainActivity, d: SettingDef) {
    val col = vbox(act, 18)
    fun section(title: String, body: String) {
        if (body.isBlank()) return
        col.addView(label(act, title, 12f, C.accent, bold = true))
        col.addView(space(act, 3))
        col.addView(label(act, body, 14f, C.text))
        col.addView(space(act, 12))
    }
    section("Назначение", d.info.str("purpose"))
    section("Влияние на результат", d.info.str("effect"))
    section("Скорость, память и размер файлов", d.info.str("performance"))
    section("Ограничения", d.info.str("limits"))
    section("Пример", d.info.str("example"))
    col.addView(label(act, "Ключ: ${d.key}  ·  по умолчанию: ${formatDefault(d)}" + (if (d.isLimit) "\n0 означает «без ограничения пользователя»; технические пределы безопасности остаются." else ""), 11f, C.muted, mono = true))
    AlertDialog.Builder(act).setTitle(d.title).setView(withScroll(act, col)).setPositiveButton("Закрыть", null).show()
}

fun formatDefault(d: SettingDef): String {
    val v = SettingsStore.profile(SettingsStore.profileId)?.values?.opt(d.key) ?: d.def
    return formatValue(d, v)
}

fun formatValue(d: SettingDef, v: Any?): String = when {
    v == null -> "—"
    v is Boolean -> if (v) "включено" else "выключено"
    d.kind == "enum" -> d.options.firstOrNull { it.first == v.toString() }?.second ?: v.toString()
    d.kind == "flags" && v is org.json.JSONArray -> {
        val items = (0 until v.length()).map { i -> d.options.firstOrNull { it.first == v.optString(i) }?.second ?: v.optString(i) }
        if (items.isEmpty()) "ничего" else items.joinToString(", ")
    }
    v is Number && d.isLimit && v.toLong() == 0L -> "0 (без ограничения)"
    else -> v.toString()
}

fun textOf(v: TextView): String = v.text.toString()
