package com.kratos.dump

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps the process in the foreground while an analysis runs. The analysis itself runs in [RunController]; this service only holds the
 * notification. On Android 13+ the notification stays hidden until the user allows notifications in system settings, the service still works.
 */
class AnalysisService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel(this)
        val n = build(this, "Анализ выполняется", "", 0, 0, true)
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else startForeground(ID, n)
        } catch (e: Exception) {
            Session.log(3, "app", "не удалось перевести службу в фоновый режим: ${e.message}")
        }
        return START_NOT_STICKY
    }

    companion object {
        private const val CHANNEL = "kratos_run"
        private const val ID = 1001
        private const val ID_DONE = 1002

        private fun ensureChannel(ctx: Context) {
            if (Build.VERSION.SDK_INT >= 26) {
                val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                if (nm.getNotificationChannel(CHANNEL) == null) {
                    nm.createNotificationChannel(NotificationChannel(CHANNEL, "Анализ", NotificationManager.IMPORTANCE_LOW))
                }
            }
        }

        @Suppress("DEPRECATION")
        private fun build(ctx: Context, title: String, text: String, done: Int, total: Int, ongoing: Boolean): Notification {
            val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(ctx, CHANNEL) else Notification.Builder(ctx)
            b.setSmallIcon(R.drawable.ic_stat_kratos).setContentTitle(title).setContentText(text).setOngoing(ongoing).setOnlyAlertOnce(true)
            if (ongoing) {
                if (total > 0) b.setProgress(100, (done * 100L / total).toInt().coerceIn(0, 100), false) else b.setProgress(0, 0, true)
            }
            val open = Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            b.setContentIntent(PendingIntent.getActivity(ctx, 0, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            return b.build()
        }

        fun start(ctx: Context) {
            val i = Intent(ctx, AnalysisService::class.java)
            try {
                if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
            } catch (e: Exception) {
                Session.log(3, "app", "фоновая служба не запущена: ${e.message}; анализ продолжится, пока приложение открыто")
            }
        }

        fun update(ctx: Context, text: String, done: Long, total: Long) {
            try {
                ensureChannel(ctx)
                val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                val pct = if (total > 0) (done * 100 / total).toInt() else 0
                nm.notify(ID, build(ctx, "Анализ выполняется", text, pct, 100, true))
            } catch (_: Exception) {
            }
        }

        fun stop(ctx: Context) {
            try {
                ctx.stopService(Intent(ctx, AnalysisService::class.java))
            } catch (_: Exception) {
            }
        }

        fun notifyDone(ctx: Context, title: String, text: String) {
            try {
                ensureChannel(ctx)
                val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(ID_DONE, build(ctx, title, text, 0, 0, false))
            } catch (_: Exception) {
            }
        }
    }
}
