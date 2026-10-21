package com.kratos.dump

import org.json.JSONArray
import org.json.JSONObject

/** One entry of the settings registry shipped by the native layer. */
class SettingDef(val o: JSONObject) {
    val key: String = o.str("key")
    val category: String = o.str("category")
    val title: String = o.str("title")
    val kind: String = o.str("kind")
    val scope: String = o.str("scope", "native")
    val advanced: Boolean = o.bool("advanced")
    val def: Any? = if (o.isNull("default")) null else o.opt("default")
    val min: Double = o.optDouble("min", 0.0)
    val max: Double = o.optDouble("max", 0.0)
    val options: List<Pair<String, String>> = buildList { o.arr("options").forEachObject { add(it.str("value") to it.str("label")) } }
    val info: JSONObject = o.obj("info")
    val isLimit: Boolean get() = key.startsWith("limits.")
}

class CategoryDef(val id: String, val title: String, val description: String)

class ProfileDef(val id: String, val title: String, val description: String, val values: JSONObject)

/**
 * Settings model. The registry comes from the native layer (single source of truth); the app only stores the keys
 * that differ from the selected profile.
 */
object SettingsStore {
    private var schema: JSONObject? = null
    lateinit var categories: List<CategoryDef>
        private set
    lateinit var settings: List<SettingDef>
        private set
    lateinit var profiles: List<ProfileDef>
        private set
    private val byKey = HashMap<String, SettingDef>()

    var profileId: String = "standard"
        private set

    /** Incremented on every change; screens compare it to know when the effective configuration moved. */
    var version = 0
        private set
    private var overrides = JSONObject()

    /** Loads the registry and the saved configuration. Returns false when the native layer is not available. */
    @Synchronized
    fun load(): Boolean {
        if (schema != null) return true
        if (!Native.ensureLoaded()) return false
        val s = parseJson(Native.schema())
        categories = buildList { s.arr("categories").forEachObject { add(CategoryDef(it.str("id"), it.str("title"), it.str("description"))) } }
        settings = buildList { s.arr("settings").forEachObject { add(SettingDef(it)) } }
        profiles = buildList { s.arr("profiles").forEachObject { add(ProfileDef(it.str("id"), it.str("title"), it.str("description"), it.obj("values"))) } }
        byKey.clear()
        settings.forEach { byKey[it.key] = it }
        schema = s
        profileId = Prefs.profileId.takeIf { id -> profiles.any { it.id == id } } ?: "standard"
        overrides = jsonOf(Prefs.overridesJson)
        // Drop keys that no longer exist or already equal the profile value.
        val keep = JSONObject()
        for (k in overrides.keys()) if (byKey.containsKey(k) && !sameValue(overrides.opt(k), profileValue(k))) keep.put(k, overrides.get(k))
        overrides = keep
        return true
    }

    fun def(key: String): SettingDef? = byKey[key]

    fun profile(id: String): ProfileDef? = profiles.firstOrNull { it.id == id }

    private fun profileValue(key: String): Any? {
        val p = profile(profileId)
        return if (p != null && p.values.has(key)) p.values.opt(key) else byKey[key]?.def
    }

    fun value(key: String): Any? = if (overrides.has(key)) overrides.opt(key) else profileValue(key)

    fun isChanged(key: String): Boolean = overrides.has(key)

    fun changedKeys(): List<String> = overrides.keys().asSequence().toList()

    fun overridesCopy(): JSONObject = JSONObject(overrides.toString())

    fun bool(key: String): Boolean = (value(key) as? Boolean) ?: false

    fun int(key: String, def: Int = 0): Int = (value(key) as? Number)?.toInt() ?: def

    fun str(key: String): String = value(key)?.toString() ?: ""

    fun set(key: String, v: Any?) {
        if (sameValue(v, profileValue(key))) overrides.remove(key) else overrides.put(key, v)
        if (key.startsWith("config.")) {
            version++
            save()
        } else persist()
    }

    fun reset(key: String) {
        overrides.remove(key)
        persist()
    }

    /** Switches the profile; individual changes are dropped. */
    fun selectProfile(id: String) {
        if (profile(id) == null) return
        profileId = id
        overrides = JSONObject()
        persist()
    }

    /** Restores the original configuration: the standard profile without changes. */
    fun resetAll() = selectProfile("standard")

    /** Applies a saved configuration. Returns the list of problems reported by the native validator. */
    fun apply(base: String, ov: JSONObject): List<String> {
        val bid = if (profile(base) != null) base else "standard"
        val v = parseJson(Native.validateConfig(bid, ov.toString()))
        val problems = buildList { v.arr("issues").forEachObject { add("${it.str("key")}: ${it.str("message")}") } }
        val values = v.obj("values")
        profileId = bid
        val keep = JSONObject()
        for (k in ov.keys()) {
            if (!byKey.containsKey(k) || !values.has(k)) continue
            val eff = values.opt(k)
            if (!sameValue(eff, profileValue(k))) keep.put(k, eff)
        }
        overrides = keep
        persist()
        return problems
    }

    /** Settings consumed by the engine. UI-scope keys are sent too (the registry knows them), harmless for the engine. */
    fun overridesForRun(): String = overrides.toString()

    private fun persist() {
        version++
        if (bool("config.autosave")) save() else pendingDirty = true
    }

    var pendingDirty = false
        private set

    /** Writes the configuration now (always used for config.* keys, and by the Save button when config.autosave is off). */
    fun save() {
        if (bool("config.auto_backup")) {
            Prefs.backupJson = JSONObject().put("base", Prefs.profileId).put("overrides", jsonOf(Prefs.overridesJson)).toString()
        }
        Prefs.overridesJson = overrides.toString()
        Prefs.profileId = profileId
        pendingDirty = false
    }

    fun hasBackup(): Boolean = Prefs.backupJson.isNotEmpty()

    fun restoreBackup(): List<String> {
        val b = jsonOf(Prefs.backupJson)
        return apply(b.str("base", "standard"), b.obj("overrides"))
    }

    // ------------------------------------------------------------------ user profiles and files
    fun exportJson(name: String): String = JSONObject()
        .put("kratos_profile", 1)
        .put("name", name)
        .put("base", profileId)
        .put("overrides", overridesCopy())
        .toString(2)

    /** Parses a profile file. Returns (base, overrides) or null when the text is not a KRATOS profile. */
    fun parseProfile(text: String): Triple<String, String, JSONObject>? {
        val o = try { JSONObject(text) } catch (e: Exception) { return null }
        if (o.optInt("kratos_profile", 0) != 1 || o.optJSONObject("overrides") == null) return null
        return Triple(o.str("name", "Импортированный"), o.str("base", "standard"), o.obj("overrides"))
    }

    fun userProfiles(): JSONObject = jsonOf(Prefs.userProfilesJson)

    fun saveUserProfile(name: String) {
        val all = userProfiles()
        all.put(name, JSONObject().put("base", profileId).put("overrides", overridesCopy()))
        Prefs.userProfilesJson = all.toString()
    }

    fun deleteUserProfile(name: String) {
        val all = userProfiles()
        all.remove(name)
        Prefs.userProfilesJson = all.toString()
    }

    private fun uniqueProfileName(base: String): String {
        val all = userProfiles()
        if (!all.has(base)) return base
        var i = 2
        while (all.has("$base $i")) i++
        return "$base $i"
    }

    /** Copies a saved profile under a new unique name; returns that name, or null when the profile does not exist. */
    fun duplicateUserProfile(name: String): String? {
        val all = userProfiles()
        val src = all.optJSONObject(name) ?: return null
        val copy = uniqueProfileName("$name (копия)")
        all.put(copy, JSONObject(src.toString()))
        Prefs.userProfilesJson = all.toString()
        return copy
    }

    /** Renames a saved profile; false when the new name is empty or taken, or the profile does not exist. */
    fun renameUserProfile(old: String, new: String): Boolean {
        val all = userProfiles()
        val src = all.optJSONObject(old) ?: return false
        if (new.isBlank() || (new != old && all.has(new))) return false
        all.remove(old)
        all.put(new, src)
        Prefs.userProfilesJson = all.toString()
        return true
    }

    fun isDefaultValue(key: String): Boolean = !isChanged(key)

    fun sameValue(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == b
        if (a is Number && b is Number) return a.toDouble() == b.toDouble()
        if (a is JSONArray && b is JSONArray) {
            if (a.length() != b.length()) return false
            val sa = (0 until a.length()).map { a.optString(it) }.sorted()
            val sb = (0 until b.length()).map { b.optString(it) }.sorted()
            return sa == sb
        }
        return a == b
    }
}
