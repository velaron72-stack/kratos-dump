package com.kratos.dump

import android.app.AlertDialog
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import org.json.JSONArray

class SettingsScreen(act: MainActivity) : Screen(act) {
    override val title = "Настройки"

    private var query = ""
    private val expanded = HashSet<String>().apply { add("general") }
    private lateinit var list: LinearLayout
    private lateinit var profileRow: LinearLayout
    private lateinit var saveBtn: View

    override fun build(): View {
        val ctx = act
        val root = vbox(ctx)

        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, "Настройки", 18f, C.text, bold = true), lp(w = 0, weight = 1f))
        saveBtn = primaryButton(ctx, "Сохранить") {
            SettingsStore.save()
            act.toast("Настройки сохранены")
            updateSaveButton()
        }.also { (it as android.widget.Button).minHeight = ctx.dp(40); it.minimumHeight = ctx.dp(40) }
        bar.addView(saveBtn)
        root.addView(bar)

        val search = editText(ctx, "Поиск по настройкам", "") { }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString()?.trim()?.lowercase() ?: ""
                rebuildList()
            }
        })
        root.addView(search, lp().apply { leftMargin = ctx.dp(14); rightMargin = ctx.dp(14); bottomMargin = ctx.dp(8) })

        profileRow = hbox(ctx, 0)
        val hs = HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
            addView(profileRow)
        }
        root.addView(hs, lp().apply { leftMargin = ctx.dp(14); rightMargin = ctx.dp(14); bottomMargin = ctx.dp(6) })

        val actions = hbox(ctx, 0)
        actions.addView(ghostButton(ctx, "Мои профили") { showUserProfiles() })
        actions.addView(hspace(ctx, 6))
        actions.addView(ghostButton(ctx, "Экспорт") { exportProfile() })
        actions.addView(hspace(ctx, 6))
        actions.addView(ghostButton(ctx, "Импорт") { importProfile() })
        actions.addView(hspace(ctx, 6))
        actions.addView(ghostButton(ctx, "Сбросить всё") { resetAll() })
        if (SettingsStore.hasBackup()) {
            actions.addView(hspace(ctx, 6))
            actions.addView(ghostButton(ctx, "Из копии") { restoreBackup() })
        }
        val hs2 = HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
            addView(actions)
        }
        root.addView(hs2, lp().apply { leftMargin = ctx.dp(14); rightMargin = ctx.dp(14); bottomMargin = ctx.dp(8) })
        root.addView(divider(ctx))

        list = vbox(ctx, 14)
        root.addView(scroll(ctx, list), lp(h = 0, weight = 1f))
        paintProfiles()
        rebuildList()
        updateSaveButton()
        return root
    }

    override fun onHide() {
        act.hideKeyboard()
    }

    override fun onBack(): Boolean {
        if (SettingsStore.pendingDirty) {
            AlertDialog.Builder(act).setMessage("Есть несохранённые изменения (автосохранение выключено). Изменения действуют до закрытия приложения; сохранить их?")
                .setPositiveButton("Сохранить") { _, _ -> SettingsStore.save(); act.pop() }
                .setNegativeButton("Не сохранять") { _, _ -> act.pop() }
                .setNeutralButton("Остаться", null).show()
            return true
        }
        return false
    }

    private fun updateSaveButton() {
        saveBtn.visibility = if (SettingsStore.pendingDirty) View.VISIBLE else View.GONE
    }

    // ------------------------------------------------------------------ profiles
    private fun paintProfiles() {
        profileRow.removeAllViews()
        for (p in SettingsStore.profiles) {
            val sel = p.id == SettingsStore.profileId
            val label = p.title.removeSuffix(" анализ")
            profileRow.addView(chip(act, label, sel) { chooseProfile(p.id) }, lp(w = LinearLayout.LayoutParams.WRAP_CONTENT).apply { rightMargin = act.dp(6) })
        }
        val changed = SettingsStore.changedKeys().size
        if (changed > 0) profileRow.addView(label(act, "изменено параметров: $changed", 12f, C.warn).apply { setPadding(act.dp(8), 0, 0, 0) })
    }

    private fun chooseProfile(id: String) {
        if (id == SettingsStore.profileId && SettingsStore.changedKeys().isEmpty()) return
        val go = {
            SettingsStore.selectProfile(id)
            paintProfiles()
            rebuildList()
            updateSaveButton()
        }
        if (SettingsStore.changedKeys().isNotEmpty())
            AlertDialog.Builder(act).setMessage("Профиль «${SettingsStore.profile(id)?.title}» заменит все отдельные изменения (${SettingsStore.changedKeys().size}). Продолжить?")
                .setPositiveButton("Продолжить") { _, _ -> go() }.setNegativeButton("Отмена", null).show()
        else go()
    }

    private fun resetAll() {
        AlertDialog.Builder(act).setMessage("Восстановить исходную конфигурацию: стандартный профиль без изменений?")
            .setPositiveButton("Восстановить") { _, _ ->
                SettingsStore.resetAll()
                paintProfiles()
                rebuildList()
                updateSaveButton()
            }.setNegativeButton("Отмена", null).show()
    }

    private fun restoreBackup() {
        val issues = SettingsStore.restoreBackup()
        paintProfiles()
        rebuildList()
        updateSaveButton()
        act.toast("Конфигурация восстановлена из резервной копии" + if (issues.isNotEmpty()) " (замечаний: ${issues.size})" else "")
    }

    private fun showUserProfiles() {
        val names = SettingsStore.userProfiles().keys().asSequence().toList().sorted()
        val items = (names + "Сохранить текущие настройки как…").toTypedArray()
        AlertDialog.Builder(act).setTitle("Мои профили").setItems(items) { _, which ->
            if (which < names.size) profileActions(names[which]) else saveAs()
        }.setNegativeButton("Закрыть", null).show()
    }

    private fun profileActions(name: String) {
        val acts = arrayOf("Применить", "Дублировать", "Переименовать", "Удалить")
        AlertDialog.Builder(act).setTitle(name).setItems(acts) { _, i ->
            when (i) {
                0 -> applyUserProfile(name)
                1 -> {
                    val copy = SettingsStore.duplicateUserProfile(name)
                    act.toast(if (copy != null) "Создан профиль «$copy»" else "Профиль не найден")
                }
                2 -> renameUserProfile(name)
                else -> AlertDialog.Builder(act).setMessage("Удалить профиль «$name»? Файлы результатов не затрагиваются.")
                    .setPositiveButton("Удалить") { _, _ ->
                        SettingsStore.deleteUserProfile(name)
                        act.toast("Профиль «$name» удалён")
                    }.setNegativeButton("Отмена", null).show()
            }
        }.setNegativeButton("Назад") { _, _ -> showUserProfiles() }.show()
    }

    private fun applyUserProfile(name: String) {
        val o = SettingsStore.userProfiles().optJSONObject(name) ?: return
        val issues = SettingsStore.apply(o.str("base", "standard"), o.obj("overrides"))
        paintProfiles(); rebuildList(); updateSaveButton()
        act.toast("Профиль «$name» применён" + if (issues.isNotEmpty()) " (замечаний: ${issues.size})" else "")
    }

    private fun renameUserProfile(old: String) {
        val input = EditText(act).apply { setText(old); setTextColor(C.text); setHintTextColor(C.muted); isSingleLine = true }
        AlertDialog.Builder(act).setTitle("Переименовать профиль").setView(input)
            .setPositiveButton("Переименовать") { _, _ ->
                val n = input.text.toString().trim()
                act.toast(if (SettingsStore.renameUserProfile(old, n)) "Профиль переименован: «$n»" else "Имя пустое или уже занято")
            }.setNegativeButton("Отмена", null).show()
    }

    private fun saveAs() {
        val input = EditText(act).apply { hint = "Название профиля"; setTextColor(C.text); setHintTextColor(C.muted); isSingleLine = true }
        AlertDialog.Builder(act).setTitle("Сохранить профиль").setView(input)
            .setPositiveButton("Сохранить") { _, _ ->
                val n = input.text.toString().trim()
                if (n.isEmpty()) act.toast("Название не задано")
                else {
                    SettingsStore.saveUserProfile(n)
                    act.toast("Профиль «$n» сохранён")
                }
            }.setNegativeButton("Отмена", null).show()
    }

    private fun exportProfile() {
        val name = SettingsStore.profile(SettingsStore.profileId)?.id ?: "profile"
        act.saveText("kratos-profile-$name.json", SettingsStore.exportJson(name))
    }

    private fun importProfile() {
        act.loadText { text ->
            val p = SettingsStore.parseProfile(text)
            if (p == null) {
                AlertDialog.Builder(act).setMessage("Файл не является профилем KRATOS DUMP.").setPositiveButton("OK", null).show()
                return@loadText
            }
            val issues = SettingsStore.apply(p.second, p.third)
            paintProfiles(); rebuildList(); updateSaveButton()
            val msg = "Профиль «${p.first}» применён." + if (issues.isEmpty()) "" else "\n\nЗамечания:\n• " + issues.take(10).joinToString("\n• ")
            AlertDialog.Builder(act).setMessage(msg).setPositiveButton("OK", null).show()
        }
    }

    // ------------------------------------------------------------------ list
    private fun matches(d: SettingDef): Boolean {
        if (query.isEmpty()) return true
        val hay = (d.title + " " + d.key + " " + d.info.str("purpose") + " " + d.options.joinToString(" ") { it.second }).lowercase()
        return query.split(' ').filter { it.isNotEmpty() }.all { hay.contains(it) }
    }

    private fun rebuildList() {
        val ctx = act
        list.removeAllViews()
        var any = false
        for (cat in SettingsStore.categories) {
            val items = SettingsStore.settings.filter { it.category == cat.id && matches(it) }
            if (items.isEmpty()) continue
            any = true
            val open = query.isNotEmpty() || cat.id in expanded
            val changed = items.count { SettingsStore.isChanged(it.key) }
            val head = card(ctx) {
                if (cat.id in expanded) expanded.remove(cat.id) else expanded.add(cat.id)
                rebuildList()
            }
            val row = hbox(ctx)
            val tb = vbox(ctx)
            tb.addView(label(ctx, cat.title, 15f, C.text, bold = true))
            if (cat.description.isNotEmpty()) tb.addView(label(ctx, cat.description, 12f, C.muted))
            row.addView(tb, lp(w = 0, weight = 1f))
            row.addView(label(ctx, (if (changed > 0) "изм. $changed · " else "") + "${items.size}  " + (if (open) "▾" else "▸"), 12f, if (changed > 0) C.warn else C.muted))
            head.addView(row)
            list.addView(head, lp().apply { topMargin = ctx.dp(8) })
            if (open) {
                val body = vbox(ctx, 4)
                for (d in items) {
                    body.addView(settingRow(d))
                    body.addView(divider(ctx))
                }
                list.addView(body)
            }
        }
        if (!any) list.addView(label(ctx, "Ничего не найдено. Поиск идёт по названию, описанию и ключу параметра.", 13f, C.muted).apply { setPadding(0, ctx.dp(20), 0, 0) })
        list.addView(space(ctx, 24))
    }

    private fun settingRow(d: SettingDef): View {
        val ctx = act
        val col = vbox(ctx)
        col.setPadding(ctx.dp(4), ctx.dp(10), ctx.dp(4), ctx.dp(10))
        val top = hbox(ctx)
        val titleView = label(ctx, d.title + (if (d.advanced) "  · расширенный" else "") + (if (d.scope == "ui") "  · интерфейс" else ""), 14f, C.text)
        top.addView(titleView, lp(w = 0, weight = 1f))
        val info = label(ctx, "ⓘ", 18f, C.accent).apply {
            setPadding(ctx.dp(10), ctx.dp(4), ctx.dp(10), ctx.dp(4))
            setOnClickListener { showSettingInfo(act, d) }
        }
        top.addView(info)
        if (SettingsStore.isChanged(d.key)) {
            top.addView(label(ctx, "↺", 18f, C.warn).apply {
                setPadding(ctx.dp(10), ctx.dp(4), ctx.dp(6), ctx.dp(4))
                setOnClickListener {
                    SettingsStore.reset(d.key)
                    paintProfiles()
                    rebuildList()
                    updateSaveButton()
                }
            })
        }
        val value = SettingsStore.value(d.key)
        when (d.kind) {
            "bool" -> {
                val sw = Switch(ctx).apply {
                    isChecked = value as? Boolean ?: false
                    setOnCheckedChangeListener { _: CompoundButton, on: Boolean -> changed(d, on) }
                }
                top.addView(sw)
                col.addView(top)
            }
            "enum" -> {
                col.addView(top)
                col.addView(valueButton(formatValue(d, value)) { pickEnum(d) })
            }
            "flags" -> {
                col.addView(top)
                col.addView(valueButton(formatValue(d, value)) { pickFlags(d) })
            }
            else -> {
                col.addView(top)
                val number = d.kind == "int" || d.kind == "number"
                val holder = arrayOfNulls<EditText>(1)
                val et = editText(ctx, "", value?.toString() ?: "", number) { txt -> commitText(d, txt, holder[0]) }
                holder[0] = et
                col.addView(et, lp().apply { topMargin = ctx.dp(6) })
                if (number) {
                    val hint = if (d.min < d.max) "допустимо ${fmt(d.min)}…${fmt(d.max)}" else ""
                    val zero = if (d.isLimit) "0 — без ограничения пользователя" else ""
                    val h = listOf(hint, zero).filter { it.isNotEmpty() }.joinToString(" · ")
                    if (h.isNotEmpty()) col.addView(label(ctx, h, 11f, C.muted).apply { setPadding(0, ctx.dp(4), 0, 0) })
                }
            }
        }
        col.addView(label(ctx, d.key, 10f, C.debug, mono = true).apply { setPadding(0, ctx.dp(4), 0, 0) })
        return col
    }

    private fun fmt(v: Double): String = if (v == Math.floor(v) && Math.abs(v) < 1e15) v.toLong().toString() else v.toString()

    private fun valueButton(text: String, onClick: () -> Unit): TextView = label(act, text, 13f, C.accent).apply {
        background = roundRect(act, C.panel2, C.border, 10)
        setPadding(act.dp(12), act.dp(10), act.dp(12), act.dp(10))
        gravity = Gravity.START
        setOnClickListener { onClick() }
        (layoutParams as? LinearLayout.LayoutParams)?.topMargin = act.dp(6)
    }

    private fun changed(d: SettingDef, v: Any?, rebuild: Boolean = true) {
        SettingsStore.set(d.key, v)
        paintProfiles()
        updateSaveButton()
        // Text fields are committed when they lose focus: rebuilding then would destroy the field that just received focus.
        if (rebuild) rebuildList()
    }

    private fun commitText(d: SettingDef, txt: String, field: EditText?) {
        val t = txt.trim()
        when (d.kind) {
            "int" -> {
                val n = t.toLongOrNull()
                if (n == null) {
                    act.toast("${d.title}: нужно целое число")
                    field?.setText(SettingsStore.value(d.key)?.toString() ?: "")
                    return
                }
                var v = n
                if (d.min < d.max) {
                    val c = v.coerceIn(d.min.toLong(), d.max.toLong())
                    if (c != v) act.toast("${d.title}: значение изменено на $c (допустимо ${fmt(d.min)}…${fmt(d.max)})")
                    v = c
                }
                if (field != null && field.text.toString() != v.toString()) field.setText(v.toString())
                if ((SettingsStore.value(d.key) as? Number)?.toLong() != v) changed(d, v, rebuild = false)
            }
            "number" -> {
                val n = t.replace(',', '.').toDoubleOrNull()
                if (n == null) {
                    act.toast("${d.title}: нужно число")
                    field?.setText(SettingsStore.value(d.key)?.toString() ?: "")
                    return
                }
                val v = if (d.min < d.max) n.coerceIn(d.min, d.max) else n
                if (field != null && field.text.toString() != v.toString()) field.setText(v.toString())
                if ((SettingsStore.value(d.key) as? Number)?.toDouble() != v) changed(d, v, rebuild = false)
            }
            else -> if (SettingsStore.value(d.key)?.toString() != t) changed(d, t, rebuild = false)
        }
    }

    private fun pickEnum(d: SettingDef) {
        val cur = d.options.indexOfFirst { it.first == SettingsStore.value(d.key)?.toString() }
        AlertDialog.Builder(act).setTitle(d.title)
            .setSingleChoiceItems(d.options.map { it.second }.toTypedArray(), cur) { dlg, which ->
                dlg.dismiss()
                changed(d, d.options[which].first)
            }.setNegativeButton("Отмена", null).show()
    }

    private fun pickFlags(d: SettingDef) {
        val cur = SettingsStore.value(d.key) as? JSONArray ?: JSONArray()
        val have = (0 until cur.length()).map { cur.optString(it) }.toSet()
        val checked = BooleanArray(d.options.size) { d.options[it].first in have }
        AlertDialog.Builder(act).setTitle(d.title)
            .setMultiChoiceItems(d.options.map { it.second }.toTypedArray(), checked) { _, i, on -> checked[i] = on }
            .setPositiveButton("Готово") { _, _ ->
                val a = JSONArray()
                d.options.forEachIndexed { i, o -> if (checked[i]) a.put(o.first) }
                changed(d, a)
            }.setNegativeButton("Отмена", null).show()
    }
}
