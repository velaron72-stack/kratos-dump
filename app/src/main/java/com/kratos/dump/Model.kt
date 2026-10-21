package com.kratos.dump

import org.json.JSONArray
import org.json.JSONObject

fun JSONObject.str(key: String, def: String = ""): String = if (has(key) && !isNull(key)) optString(key, def) else def
fun JSONObject.lng(key: String, def: Long = 0): Long = if (has(key) && !isNull(key)) optLong(key, def) else def
fun JSONObject.bool(key: String, def: Boolean = false): Boolean = if (has(key) && !isNull(key)) optBoolean(key, def) else def
fun JSONObject.obj(key: String): JSONObject = optJSONObject(key) ?: JSONObject()
fun JSONObject.arr(key: String): JSONArray = optJSONArray(key) ?: JSONArray()

inline fun JSONArray.forEachObject(f: (JSONObject) -> Unit) {
    for (i in 0 until length()) optJSONObject(i)?.let(f)
}

fun parseJson(text: String): JSONObject = try {
    JSONObject(text)
} catch (e: Exception) {
    JSONObject().put("ok", false).put("error", "invalid JSON from the native layer: ${e.message}")
}

/** A file chosen through the system picker. */
data class PickedFile(val uri: android.net.Uri, val name: String, val size: Long)

data class LibInfo(
    val entry: String,
    val name: String,
    val abi: String,
    val size: Long,
    val isElf: Boolean,
    val arch: String,
    val archLabel: String,
    val bits: Int,
    val littleEndian: Boolean,
    val skippedByArch: Boolean,
    val note: String,
    val nested: String,
    val rank: Int,
    val selectedAuto: Boolean,
) {
    val description: String
        get() = buildString {
            append(if (isElf) archLabel else "не ELF")
            if (isElf) append(" · ${bits}-бит · ${if (littleEndian) "LE" else "BE"}")
            if (abi.isNotEmpty()) append(" · ABI $abi")
            append(" · ${humanSize(size)}")
            if (nested.isNotEmpty()) append(" · во вложенном архиве $nested")
        }

    companion object {
        fun from(o: JSONObject) = LibInfo(
            o.str("entry"), o.str("name"), o.str("abi"), o.lng("size"), o.bool("is_elf"), o.str("arch"), o.str("arch_label"),
            o.optInt("bits"), o.bool("little_endian", true), o.bool("skipped_by_arch"), o.str("note"), o.str("nested"), o.optInt("rank"), o.bool("selected_auto"),
        )
    }
}

data class MetaInfo(val entry: String, val name: String, val handler: String, val size: Long, val status: String, val note: String) {
    companion object {
        fun from(o: JSONObject) = MetaInfo(o.str("entry"), o.str("name"), o.str("handler"), o.lng("size"), o.str("status"), o.str("note"))
    }
}

class ApkProbe(val json: JSONObject) {
    val ok = json.bool("ok")
    val error = json.str("error")
    val entries = json.lng("entries")
    val totalUncompressed = json.lng("total_uncompressed")
    val recovered = json.bool("recovered")
    val zip64 = json.bool("zip64")
    val warnings = json.arr("warnings").let { a -> (0 until a.length()).map { a.optString(it) } }
    val abis = json.arr("abis").let { a -> (0 until a.length()).map { a.optString(it) } }
    val libs: List<LibInfo> = buildList { json.arr("libs").forEachObject { add(LibInfo.from(it)) } }
    val metas: List<MetaInfo> = buildList { json.arr("metas").forEachObject { add(MetaInfo.from(it)) } }
    val nestedApks = json.arr("nested_apks").let { a -> (0 until a.length()).map { a.optString(it) } }
}

/** One finished or interrupted run, as shown in the history. */
data class HistoryEntry(
    val id: String,
    val tsMs: Long,
    val mode: String,
    val inputName: String,
    val statusId: String,
    val statusText: String,
    val runName: String,
    val treeUri: String,
    val runDocUri: String,
    val exportOk: Boolean,
    val note: String,
    val profileTitle: String = "",
    val archLabel: String = "",
    val hasMetadata: Boolean = false,
    val durationMs: Long = 0,
    val filesCount: Int = 0,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id).put("ts", tsMs).put("mode", mode).put("input", inputName).put("status_id", statusId).put("status_text", statusText)
        .put("run_name", runName).put("tree_uri", treeUri).put("run_doc_uri", runDocUri).put("export_ok", exportOk).put("note", note)
        .put("profile", profileTitle).put("arch", archLabel).put("has_metadata", hasMetadata).put("duration_ms", durationMs).put("files", filesCount)

    companion object {
        fun from(o: JSONObject) = HistoryEntry(
            o.str("id"), o.lng("ts"), o.str("mode"), o.str("input"), o.str("status_id"), o.str("status_text"), o.str("run_name"),
            o.str("tree_uri"), o.str("run_doc_uri"), o.bool("export_ok"), o.str("note"),
            o.str("profile"), o.str("arch"), o.bool("has_metadata"), o.lng("duration_ms"), o.optInt("files"),
        )

        /** Profile, architectures, metadata, duration and result count of a run, taken from its summary.json. */
        fun details(summary: JSONObject): Details {
            val run = summary.optJSONObject("run")
            val archs = LinkedHashSet<String>()
            val libs = summary.optJSONArray("libraries")
            if (libs != null) for (i in 0 until libs.length()) {
                val a = libs.optJSONObject(i)?.optJSONObject("elf")?.optString("architecture", "") ?: ""
                if (a.isNotEmpty()) archs.add(a)
            }
            val files = summary.optJSONArray("files")
            var ok = 0
            if (files != null) for (i in 0 until files.length()) if (files.optJSONObject(i)?.optBoolean("ok", false) == true) ok++
            return Details(
                run?.optString("profile_title", "") ?: "", archs.joinToString(", "), summary.optJSONObject("metadata")?.optBoolean("found", false) == true,
                run?.optLong("duration_ms", 0) ?: 0, ok,
            )
        }
    }

    class Details(val profileTitle: String, val archLabel: String, val hasMetadata: Boolean, val durationMs: Long, val filesCount: Int)
}

/** What the user chose for the metadata tile. */
sealed class MetaChoice {
    object Auto : MetaChoice()
    object None : MetaChoice()
    data class Entry(val entry: String) : MetaChoice()
    object File : MetaChoice()
}
