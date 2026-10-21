package com.kratos.dump

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.FrameLayout
import android.widget.Toast

/** One full-screen page. Screens are plain Views stacked inside [MainActivity]. */
abstract class Screen(val act: MainActivity) {
    open val title: String = ""
    abstract fun build(): View
    open fun onShow() {}
    open fun onHide() {}

    /** Return true when the back press was consumed. */
    open fun onBack(): Boolean = false
}

class MainActivity : Activity() {
    private lateinit var root: FrameLayout
    private val stack = ArrayList<Screen>()
    private val views = ArrayList<View>()
    private var pendingExportText: String? = null
    private var pendingImport: ((String) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        Session.init(this)
        window.statusBarColor = C.bg
        window.navigationBarColor = C.bg
        if (Build.VERSION.SDK_INT >= 23) window.decorView.systemUiVisibility = 0
        root = FrameLayout(this).apply { setBackgroundColor(C.bg) }
        setContentView(root)
        val loaded = SettingsStore.load()
        if (!loaded) {
            val msg = "Не удалось загрузить библиотеку анализа для этого устройства: ${Native.loadError ?: "причина неизвестна"}.\n\n" +
                "Приложение собрано для arm64-v8a и armeabi-v7a. Установите сборку под архитектуру устройства."
            Session.log(4, "app", msg)
            AlertDialog.Builder(this).setTitle("Ошибка запуска").setMessage(msg).setPositiveButton("Закрыть") { _, _ -> finish() }.setCancelable(false).show()
        }
        if (stack.isEmpty()) {
            if (!Prefs.firstRunDone) push(WelcomeScreen(this)) else push(MainScreen(this))
        }
        Session.addListener(sessionListener)
    }

    private val sessionListener = object : SessionListener {
        override fun onStateChanged() {
            // Show a finished run once, and any message that the controller left for the user.
            val msg = Session.lastMessage
            if (msg != null) {
                Session.lastMessage = null
                AlertDialog.Builder(this@MainActivity).setMessage(msg).setPositiveButton("OK", null).show()
            }
            val res = Session.lastResult
            if (res != null && Session.state == RunState.Done && !shownResults.contains(res.liveHistoryId)) {
                shownResults.add(res.liveHistoryId)
                if (stack.lastOrNull() !is ResultScreen) push(ResultScreen(this@MainActivity, res.summary, res.statusId, res.statusText, res.inputName, res.runName, res.runDocUri, res.exportOk, res.exportNote))
            }
        }
    }
    private val shownResults = HashSet<String>()

    override fun onDestroy() {
        Session.removeListener(sessionListener)
        super.onDestroy()
    }

    // ------------------------------------------------------------------ navigation
    fun push(s: Screen) {
        stack.lastOrNull()?.onHide()
        stack.add(s)
        val v = s.build()
        views.add(v)
        root.removeAllViews()
        root.addView(v, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        s.onShow()
    }

    fun pop() {
        if (stack.size <= 1) return
        stack.removeAt(stack.size - 1).onHide()
        views.removeAt(views.size - 1)
        root.removeAllViews()
        root.addView(views.last(), FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        stack.last().onShow()
    }

    /** Rebuilds the view of the top screen in place (after its own state changed). */
    fun refresh() {
        val top = stack.lastOrNull() ?: return
        val v = top.build()
        views[views.size - 1] = v
        root.removeAllViews()
        root.addView(v, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        top.onShow()
    }

    /** Replaces the whole stack with one screen. */
    fun replaceRoot(s: Screen) {
        stack.lastOrNull()?.onHide()
        stack.clear()
        views.clear()
        push(s)
    }

    override fun onBackPressed() {
        val top = stack.lastOrNull()
        if (top != null && top.onBack()) return
        if (stack.size > 1) pop() else super.onBackPressed()
    }

    override fun onResume() {
        super.onResume()
        stack.lastOrNull()?.onShow()
        Session.changed()
    }

    // ------------------------------------------------------------------ pickers
    fun pickApk() = openDocument(REQ_APK, arrayOf("application/vnd.android.package-archive", "application/zip", "application/octet-stream", "*/*"))

    fun pickLib() = openDocument(REQ_LIB, arrayOf("*/*"))

    fun pickMeta() = openDocument(REQ_META, arrayOf("*/*"))

    private fun openDocument(code: Int, types: Array<String>) {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, types)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        }
        launch(i, code)
    }

    fun pickOutput() {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
            val t = Session.outTree
            if (t != null && Build.VERSION.SDK_INT >= 26) putExtra(DocumentsContract.EXTRA_INITIAL_URI, t)
        }
        launch(i, REQ_OUT)
    }

    /** Offers to save a text file (a settings profile) through the system file dialog. */
    fun saveText(suggestedName: String, text: String) {
        pendingExportText = text
        val i = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, suggestedName)
        }
        launch(i, REQ_EXPORT_TEXT)
    }

    fun loadText(callback: (String) -> Unit) {
        pendingImport = callback
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        launch(i, REQ_IMPORT_TEXT)
    }

    fun openFolder(docUri: String) {
        if (docUri.isEmpty()) return
        val i = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(Uri.parse(docUri), DocumentsContract.Document.MIME_TYPE_DIR)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        try {
            startActivity(i)
        } catch (e: Exception) {
            toast("Не удалось открыть папку: встроенный файловый менеджер недоступен")
        }
    }

    private fun launch(i: Intent, code: Int) {
        try {
            startActivityForResult(i, code)
        } catch (e: ActivityNotFoundException) {
            toast("На устройстве нет системного выбора файлов")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data == null) return
        val uri = data.data ?: return
        when (requestCode) {
            REQ_APK -> confirmReplace(Session.lib != null, "Выбор APK заменит выбранную отдельную библиотеку. Продолжить?") { Session.chooseApk(uri) }
            REQ_LIB -> confirmReplace(Session.apk != null, "Анализ отдельной библиотеки заменит выбранный APK. Продолжить?") { Session.chooseLib(uri) }
            REQ_META -> Session.chooseMetaFile(uri)
            REQ_OUT -> Session.chooseOutput(uri)
            REQ_EXPORT_TEXT -> {
                val t = pendingExportText ?: return
                pendingExportText = null
                try {
                    contentResolver.openOutputStream(uri, "wt")?.use { it.write(t.toByteArray(Charsets.UTF_8)) } ?: throw IllegalStateException("файл не открылся")
                    toast("Профиль сохранён")
                } catch (e: Exception) {
                    toast("Профиль не сохранён: ${e.message}")
                }
            }
            REQ_IMPORT_TEXT -> {
                val cb = pendingImport ?: return
                pendingImport = null
                val txt = Saf.readAll(this, uri, 1 shl 20)
                if (txt == null) toast("Файл не прочитан") else cb(txt)
            }
        }
    }

    private fun confirmReplace(needed: Boolean, msg: String, action: () -> Unit) {
        if (!needed) {
            action()
            return
        }
        AlertDialog.Builder(this).setMessage(msg).setPositiveButton("Продолжить") { _, _ -> action() }.setNegativeButton("Отмена", null).show()
    }

    fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    companion object {
        const val REQ_APK = 1
        const val REQ_LIB = 2
        const val REQ_META = 3
        const val REQ_OUT = 4
        const val REQ_EXPORT_TEXT = 5
        const val REQ_IMPORT_TEXT = 6
    }
}
