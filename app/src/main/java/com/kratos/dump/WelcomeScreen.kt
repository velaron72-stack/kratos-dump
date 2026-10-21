package com.kratos.dump

import android.view.Gravity
import android.view.View

class WelcomeScreen(act: MainActivity) : Screen(act) {
    override fun build(): View {
        val ctx = act
        val col = vbox(ctx, 24).apply { gravity = Gravity.CENTER_HORIZONTAL }
        col.addView(space(ctx, 40))
        col.addView(label(ctx, "KRATOS", 15f, C.accent, bold = true).apply { letterSpacing = 0.4f })
        col.addView(space(ctx, 4))
        col.addView(label(ctx, "DUMP", 44f, C.text, bold = true))
        col.addView(space(ctx, 18))
        col.addView(label(ctx, "Анализ APK и нативных библиотек .so: структура ELF, символы, функции, строки, ссылки, дизассемблирование и честный отчёт о полноте результата.", 15f, C.muted))
        col.addView(space(ctx, 28))
        for ((t, d) in listOf(
            "Выберите файл" to "APK или отдельную .so. Библиотеки и метаданные в APK находятся автоматически, выбор можно изменить.",
            "Укажите папку" to "Результаты создаются в «android_dump/имя_дата_время» внутри выбранной папки. Исходные файлы не изменяются.",
            "Получите отчёты" to "dump, функции, строки, ссылки, дизассемблирование и полнота анализа. Сбои этапов не скрываются.",
        )) {
            val c = card(ctx)
            c.addView(label(ctx, t, 15f, C.text, bold = true))
            c.addView(space(ctx, 4))
            c.addView(label(ctx, d, 13f, C.muted))
            col.addView(c, lp().apply { bottomMargin = ctx.dp(10) })
        }
        col.addView(space(ctx, 8))
        col.addView(label(ctx, "Разрешения не нужны: файлы и папки выбираются через системный выбор Android, root не требуется.", 12f, C.muted))
        col.addView(space(ctx, 20))
        col.addView(primaryButton(ctx, "Начать работу") {
            Prefs.firstRunDone = true
            act.replaceRoot(MainScreen(act))
        }, lp())
        return scroll(ctx, col)
    }
}
