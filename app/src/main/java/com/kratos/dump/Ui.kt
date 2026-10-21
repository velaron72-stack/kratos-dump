package com.kratos.dump

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Colors and small view factories for the dark minimal look. No AndroidX and no layout XML. */
object C {
    val bg = Color.parseColor("#0B0C0E")
    val panel = Color.parseColor("#14161A")
    val panel2 = Color.parseColor("#1B1E24")
    val border = Color.parseColor("#262A32")
    val text = Color.parseColor("#E6E8EB")
    val muted = Color.parseColor("#8A919C")
    val accent = Color.parseColor("#3DD6B5")
    val onAccent = Color.parseColor("#06110F")
    val ok = Color.parseColor("#4ADE80")
    val warn = Color.parseColor("#FBBF24")
    val err = Color.parseColor("#F87171")
    val debug = Color.parseColor("#6B7280")
}

fun Context.dp(v: Int): Int = (v * resources.displayMetrics.density + 0.5f).toInt()

fun Context.dpf(v: Float): Float = v * resources.displayMetrics.density

fun roundRect(ctx: Context, fill: Int, stroke: Int = 0, radiusDp: Int = 14, strokeDp: Int = 1): GradientDrawable =
    GradientDrawable().apply {
        setColor(fill)
        cornerRadius = ctx.dpf(radiusDp.toFloat())
        if (stroke != 0) setStroke(ctx.dp(strokeDp), stroke)
    }

fun label(ctx: Context, text: CharSequence, sizeSp: Float = 14f, color: Int = C.text, bold: Boolean = false, mono: Boolean = false): TextView =
    TextView(ctx).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTextColor(color)
        if (mono) typeface = Typeface.MONOSPACE
        if (bold) setTypeface(typeface, Typeface.BOLD)
        includeFontPadding = false
        setLineSpacing(0f, 1.15f)
    }

fun lp(w: Int = ViewGroup.LayoutParams.MATCH_PARENT, h: Int = ViewGroup.LayoutParams.WRAP_CONTENT, weight: Float = 0f): LinearLayout.LayoutParams =
    LinearLayout.LayoutParams(w, h, weight)

fun vbox(ctx: Context, pad: Int = 0): LinearLayout = LinearLayout(ctx).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(ctx.dp(pad), ctx.dp(pad), ctx.dp(pad), ctx.dp(pad))
}

fun hbox(ctx: Context, pad: Int = 0): LinearLayout = LinearLayout(ctx).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    setPadding(ctx.dp(pad), ctx.dp(pad), ctx.dp(pad), ctx.dp(pad))
}

fun space(ctx: Context, hDp: Int): View = View(ctx).apply { layoutParams = lp(h = ctx.dp(hDp)) }

fun hspace(ctx: Context, wDp: Int): View = View(ctx).apply { layoutParams = lp(w = ctx.dp(wDp), h = 1) }

fun divider(ctx: Context): View = View(ctx).apply {
    setBackgroundColor(C.border)
    layoutParams = lp(h = 1)
}

/** A rounded panel; [onClick] makes it a tile. */
fun card(ctx: Context, onClick: (() -> Unit)? = null): LinearLayout = vbox(ctx, 14).apply {
    background = roundRect(ctx, C.panel, C.border)
    if (onClick != null) {
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
    }
}

fun primaryButton(ctx: Context, text: String, onClick: () -> Unit): Button = Button(ctx).apply {
    this.text = text
    isAllCaps = false
    setTextColor(C.onAccent)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
    setTypeface(typeface, Typeface.BOLD)
    background = roundRect(ctx, C.accent, 0, 14)
    stateListAnimator = null
    minHeight = ctx.dp(52)
    setOnClickListener { onClick() }
}

fun ghostButton(ctx: Context, text: String, onClick: () -> Unit): Button = Button(ctx).apply {
    this.text = text
    isAllCaps = false
    setTextColor(C.text)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
    background = roundRect(ctx, C.panel2, C.border, 12)
    stateListAnimator = null
    minHeight = ctx.dp(40)
    minimumHeight = ctx.dp(40)
    setPadding(ctx.dp(12), 0, ctx.dp(12), 0)
    setOnClickListener { onClick() }
}

fun chip(ctx: Context, text: String, selected: Boolean, onClick: () -> Unit): TextView = TextView(ctx).apply {
    this.text = text
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
    setTextColor(if (selected) C.onAccent else C.text)
    background = roundRect(ctx, if (selected) C.accent else C.panel2, if (selected) C.accent else C.border, 18)
    setPadding(ctx.dp(14), ctx.dp(8), ctx.dp(14), ctx.dp(8))
    gravity = Gravity.CENTER
    setOnClickListener { onClick() }
}

fun editText(ctx: Context, hint: String, value: String, number: Boolean = false, onDone: (String) -> Unit): EditText = EditText(ctx).apply {
    setText(value)
    this.hint = hint
    setTextColor(C.text)
    setHintTextColor(C.muted)
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
    background = roundRect(ctx, C.panel2, C.border, 10)
    setPadding(ctx.dp(12), ctx.dp(10), ctx.dp(12), ctx.dp(10))
    isSingleLine = true
    imeOptions = EditorInfo.IME_ACTION_DONE
    if (number) inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_SIGNED or InputType.TYPE_NUMBER_FLAG_DECIMAL
    setOnEditorActionListener { v, actionId, _ ->
        if (actionId == EditorInfo.IME_ACTION_DONE) {
            onDone(v.text.toString())
            v.clearFocus()
            true
        } else false
    }
    setOnFocusChangeListener { v, has -> if (!has) onDone((v as EditText).text.toString()) }
}

fun scroll(ctx: Context, child: View): ScrollView = ScrollView(ctx).apply {
    isFillViewport = true
    overScrollMode = View.OVER_SCROLL_NEVER
    addView(child, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
}

fun statusColor(id: String): Int = when (id) {
    "success", "ok" -> C.ok
    "cancelled" -> C.warn
    "not_started" -> C.muted
    else -> C.err
}

fun humanSize(bytes: Long): String {
    if (bytes < 0) return "—"
    val units = arrayOf("Б", "КБ", "МБ", "ГБ", "ТБ")
    var v = bytes.toDouble()
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    return if (i == 0) "$bytes Б" else String.format(java.util.Locale.US, "%.1f %s", v, units[i])
}

fun Activity.hideKeyboard() {
    val v = currentFocus ?: return
    (getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager).hideSoftInputFromWindow(v.windowToken, 0)
}
