package com.kratos.dump

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import android.util.TypedValue
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Scrolling log view used by the mini console and the full console screen. Settings console.* are read on every refresh. */
class ConsoleView(ctx: Context, private val sizeSp: Float, private val maxShown: Int) : ScrollView(ctx), SessionListener {
    private val text = TextView(ctx).apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        typeface = Typeface.MONOSPACE
        setTextColor(C.muted)
        setPadding(ctx.dp(10), ctx.dp(8), ctx.dp(10), ctx.dp(8))
        setTextIsSelectable(false)
    }
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    private var shown = 0
    var filterLevel = -1  // -1: follow console.min_level

    init {
        overScrollMode = OVER_SCROLL_NEVER
        addView(text)
    }

    private fun minLevel(): Int {
        if (filterLevel >= 0) return filterLevel
        return listOf("debug", "info", "ok", "warning", "error").indexOf(SettingsStore.str("console.min_level")).coerceAtLeast(0)
    }

    private fun colorOf(level: Int) = when (level) {
        0 -> C.debug
        2 -> C.ok
        3 -> C.warn
        4 -> C.err
        else -> C.text
    }

    private fun append(b: SpannableStringBuilder, l: ConsoleLine) {
        val start = b.length
        val stamp = if (SettingsStore.bool("console.timestamps")) fmt.format(Date(l.tsMs)) + " " else ""
        val stage = if (l.stage.isNotEmpty()) "[${l.stage}] " else ""
        b.append(stamp).append(stage).append(l.msg).append('\n')
        b.setSpan(ForegroundColorSpan(colorOf(l.level)), start, b.length, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    fun reload() {
        val min = minLevel()
        val lines = Session.consoleSnapshot().filter { it.level >= min }.takeLast(maxShown)
        val b = SpannableStringBuilder()
        lines.forEach { append(b, it) }
        shown = lines.size
        text.text = b
        scrollDown()
    }

    override fun onConsole(added: List<ConsoleLine>) {
        val min = minLevel()
        val vis = added.filter { it.level >= min }
        if (vis.isEmpty()) return
        if (shown + vis.size > maxShown * 2) {
            reload()
            return
        }
        val b = SpannableStringBuilder(text.text)
        vis.forEach { append(b, it) }
        shown += vis.size
        text.text = b
        scrollDown()
    }

    private fun scrollDown() {
        if (SettingsStore.bool("console.autoscroll")) post { fullScroll(View.FOCUS_DOWN) }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        Session.addListener(this)
        reload()
    }

    override fun onDetachedFromWindow() {
        Session.removeListener(this)
        super.onDetachedFromWindow()
    }

    /** The visible lines as text; with [all] every recorded line of the session, whatever the filter. */
    fun plainText(all: Boolean = false): String {
        val min = if (all) 0 else minLevel()
        val fmtFull = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
        return Session.consoleSnapshot().filter { it.level >= min }.joinToString("\n") {
            "${fmtFull.format(Date(it.tsMs))} ${listOf("DEBUG", "INFO", "OK", "WARN", "ERROR")[it.level.coerceIn(0, 4)]} [${it.stage}] ${it.msg}"
        }
    }
}

class ConsoleScreen(act: MainActivity) : Screen(act) {
    override val title = "Журнал"

    override fun build(): View {
        val ctx = act
        val col = vbox(ctx)
        val bar = hbox(ctx, 12)
        bar.addView(ghostButton(ctx, "Назад") { act.pop() })
        bar.addView(hspace(ctx, 10))
        bar.addView(label(ctx, "Журнал", 18f, C.text, bold = true), lp(w = 0, weight = 1f))
        col.addView(bar)
        val view = ConsoleView(ctx, 12f, 5000)
        val row = hbox(ctx, 8)
        val levels = listOf("Все" to 0, "Инфо" to 1, "Успех" to 2, "Предупреждения" to 3, "Ошибки" to 4)
        val chips = ArrayList<Pair<TextView, Int>>()
        fun paint() {
            val cur = if (view.filterLevel < 0) levels.indexOfFirst { it.second == listOf("debug", "info", "ok", "warning", "error").indexOf(SettingsStore.str("console.min_level")).coerceAtLeast(0) } else levels.indexOfFirst { it.second == view.filterLevel }
            row.removeAllViews()
            chips.clear()
            levels.forEachIndexed { i, (name, lv) ->
                val c = chip(ctx, name, i == cur) {
                    view.filterLevel = lv
                    view.reload()
                    paint()
                }
                row.addView(c, lp(w = LinearLayout.LayoutParams.WRAP_CONTENT).apply { rightMargin = ctx.dp(6) })
                chips.add(c to lv)
            }
        }
        paint()
        val rowScroll = android.widget.HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
            addView(row)
        }
        col.addView(rowScroll)
        val actions = hbox(ctx, 8)
        actions.addView(ghostButton(ctx, "Копировать") {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("KRATOS DUMP log", view.plainText()))
            act.toast("Журнал скопирован")
        })
        actions.addView(hspace(ctx, 8))
        actions.addView(ghostButton(ctx, "Сохранить") {
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            act.saveText("kratos-log-$stamp.txt", view.plainText(all = true))
        })
        actions.addView(hspace(ctx, 8))
        actions.addView(ghostButton(ctx, "Очистить") {
            Session.clearConsole()
            view.reload()
        })
        col.addView(actions)
        val frame = android.widget.FrameLayout(ctx)
        frame.setBackgroundColor(C.panel)
        frame.addView(view, android.widget.FrameLayout.LayoutParams(-1, -1))
        col.addView(frame, lp(h = 0, weight = 1f))
        return col
    }
}
