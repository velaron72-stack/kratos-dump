package com.kratos.dump

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Small persistent store: SharedPreferences for flags and settings, files for the history. */
object Prefs {
    private lateinit var sp: SharedPreferences
    private lateinit var historyDir: File
    private val lock = Any()

    fun init(ctx: Context) {
        if (::sp.isInitialized) return
        val app = ctx.applicationContext
        sp = app.getSharedPreferences("kratos", Context.MODE_PRIVATE)
        historyDir = File(app.filesDir, "history").also { it.mkdirs() }
    }

    var firstRunDone: Boolean
        get() = sp.getBoolean("first_run_done", false)
        set(v) = sp.edit().putBoolean("first_run_done", v).apply()

    var profileId: String
        get() = sp.getString("profile", "standard") ?: "standard"
        set(v) = sp.edit().putString("profile", v).apply()

    /** JSON object with the settings that differ from the profile. */
    var overridesJson: String
        get() = sp.getString("overrides", "{}") ?: "{}"
        set(v) = sp.edit().putString("overrides", v).apply()

    /** The previous saved configuration, kept when config.auto_backup is on. */
    var backupJson: String
        get() = sp.getString("backup", "") ?: ""
        set(v) = sp.edit().putString("backup", v).apply()

    /** Named user profiles: {"name": {"base": "standard", "overrides": {...}}}. */
    var userProfilesJson: String
        get() = sp.getString("user_profiles", "{}") ?: "{}"
        set(v) = sp.edit().putString("user_profiles", v).apply()

    var outTreeUri: String
        get() = sp.getString("out_tree", "") ?: ""
        set(v) = sp.edit().putString("out_tree", v).apply()

    // ------------------------------------------------------------------ history
    fun historyList(): List<HistoryEntry> = synchronized(lock) {
        val f = File(historyDir, "index.json")
        if (!f.isFile) return emptyList()
        try {
            val a = JSONArray(f.readText())
            buildList { for (i in 0 until a.length()) a.optJSONObject(i)?.let { add(HistoryEntry.from(it)) } }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun historyAdd(e: HistoryEntry, summaryText: String?, maxEntries: Int) = synchronized(lock) {
        val list = historyList().toMutableList()
        list.add(0, e)
        while (maxEntries > 0 && list.size > maxEntries) {
            val old = list.removeAt(list.size - 1)
            File(historyDir, "${old.id}.json").delete()
        }
        writeIndex(list)
        if (summaryText != null) File(historyDir, "${e.id}.json").writeText(summaryText)
    }

    fun historyRemove(id: String) = synchronized(lock) {
        writeIndex(historyList().filter { it.id != id })
        File(historyDir, "$id.json").delete()
    }

    fun historyClear() = synchronized(lock) {
        historyDir.listFiles()?.forEach { it.delete() }
    }

    fun historySummary(id: String): String? = synchronized(lock) {
        val f = File(historyDir, "$id.json")
        if (f.isFile) f.readText() else null
    }

    private fun writeIndex(list: List<HistoryEntry>) {
        val a = JSONArray()
        list.forEach { a.put(it.toJson()) }
        File(historyDir, "index.json").writeText(a.toString())
    }
}

fun jsonOf(text: String): JSONObject = try {
    JSONObject(text)
} catch (e: Exception) {
    JSONObject()
}
