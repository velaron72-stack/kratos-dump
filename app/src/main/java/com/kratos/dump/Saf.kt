package com.kratos.dump

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.Os
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/** Storage Access Framework helpers: file metadata, permission checks and copying a finished run into the chosen folder. */
object Saf {
    const val MIME_DIR = DocumentsContract.Document.MIME_TYPE_DIR

    // Created files always use this type: providers then keep the exact display name instead of appending an extension.
    private const val BIN = "application/octet-stream"

    fun queryFile(ctx: Context, uri: Uri): PickedFile {
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "file"
        var size = -1L
        try {
            ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0 && !c.isNull(ni)) name = c.getString(ni)
                    if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                }
            }
        } catch (_: Exception) {
        }
        if (size < 0) {
            try {
                ctx.contentResolver.openFileDescriptor(uri, "r")?.use { size = it.statSize }
            } catch (_: Exception) {
            }
        }
        return PickedFile(uri, name, size)
    }

    fun openRead(ctx: Context, uri: Uri): ParcelFileDescriptor? = try {
        ctx.contentResolver.openFileDescriptor(uri, "r")
    } catch (_: Exception) {
        null
    }

    /** Keeps read access to a picked file across restarts when the provider allows it. */
    fun keepRead(ctx: Context, uri: Uri) {
        try {
            ctx.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: Exception) {
        }
    }

    fun keepTree(ctx: Context, uri: Uri) {
        try {
            ctx.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        } catch (_: Exception) {
        }
    }

    fun hasTreePermission(ctx: Context, uri: Uri): Boolean =
        ctx.contentResolver.persistedUriPermissions.any { it.uri == uri && it.isReadPermission && it.isWritePermission }

    private fun docUri(tree: Uri, docId: String): Uri = DocumentsContract.buildDocumentUriUsingTree(tree, docId)

    fun treeRootUri(tree: Uri): Uri = docUri(tree, DocumentsContract.getTreeDocumentId(tree))

    fun fileDocUri(tree: Uri, docId: String): Uri = docUri(tree, docId)

    fun treeName(ctx: Context, tree: Uri): String = try {
        ctx.contentResolver.query(treeRootUri(tree), arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        } ?: tree.lastPathSegment ?: tree.toString()
    } catch (_: Exception) {
        tree.lastPathSegment ?: tree.toString()
    }

    /** A readable location for primary-storage URIs ("primary:Download/x" becomes "/storage/emulated/0/Download/x"); the raw id otherwise. */
    fun treePathHint(tree: Uri): String {
        val id = try {
            DocumentsContract.getTreeDocumentId(tree)
        } catch (_: Exception) {
            return tree.toString()
        }
        val i = id.indexOf(':')
        if (i < 0) return id
        val vol = id.substring(0, i)
        val rest = id.substring(i + 1)
        return (if (vol == "primary") "/storage/emulated/0/$rest" else "/storage/$vol/$rest").trimEnd('/')
    }

    class Child(val docId: String, val name: String, val mime: String, val size: Long) {
        val isDir: Boolean get() = mime == MIME_DIR
    }

    fun children(ctx: Context, tree: Uri, parentDocId: String): List<Child> {
        val out = ArrayList<Child>()
        val uri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentDocId)
        try {
            ctx.contentResolver.query(
                uri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE,
                ),
                null, null, null,
            )?.use { c ->
                while (c.moveToNext()) out.add(Child(c.getString(0), c.getString(1) ?: "", c.getString(2) ?: "", if (c.isNull(3)) -1 else c.getLong(3)))
            }
        } catch (_: Exception) {
        }
        return out
    }

    private fun createDir(ctx: Context, tree: Uri, parentDocId: String, name: String): String? = try {
        DocumentsContract.createDocument(ctx.contentResolver, docUri(tree, parentDocId), MIME_DIR, name)?.let { DocumentsContract.getDocumentId(it) }
    } catch (_: Exception) {
        null
    }

    /** Finds the child folder or creates it. Returns its document id. */
    fun ensureDir(ctx: Context, tree: Uri, parentDocId: String, name: String): String? {
        children(ctx, tree, parentDocId).firstOrNull { it.isDir && it.name == name }?.let { return it.docId }
        return createDir(ctx, tree, parentDocId, name)
    }

    class TreeCheck(val ok: Boolean, val message: String, val freeBytes: Long)

    /** Verifies that the chosen folder accepts writes and, where the provider exposes it, reports the free space. */
    fun checkTree(ctx: Context, tree: Uri): TreeCheck {
        if (!hasTreePermission(ctx, tree)) return TreeCheck(false, "доступ к папке больше не действует: выберите её заново", -1)
        val rootId = DocumentsContract.getTreeDocumentId(tree)
        val probe = try {
            DocumentsContract.createDocument(ctx.contentResolver, docUri(tree, rootId), BIN, ".kratos_probe")
        } catch (e: Exception) {
            return TreeCheck(false, "не удаётся создать файл в папке: ${e.message ?: e.javaClass.simpleName}", -1)
        } ?: return TreeCheck(false, "поставщик файлов отказал в создании файла: папка недоступна для записи", -1)
        var free = -1L
        var err: String? = null
        try {
            val pfd = ctx.contentResolver.openFileDescriptor(probe, "w")
            if (pfd == null) {
                err = "не удаётся открыть пробный файл для записи"
            } else {
                pfd.use {
                    try {
                        val sv = Os.fstatvfs(it.fileDescriptor)
                        free = sv.f_bavail * sv.f_frsize
                    } catch (_: Exception) {
                        // Some providers do not expose a real file descriptor; the free space is then unknown.
                    }
                    FileOutputStream(it.fileDescriptor).write(0)
                }
            }
        } catch (e: Exception) {
            err = "запись в папку не удалась: ${e.message ?: e.javaClass.simpleName}"
        }
        try {
            DocumentsContract.deleteDocument(ctx.contentResolver, probe)
        } catch (_: Exception) {
        }
        val e = err
        return if (e != null) TreeCheck(false, e, -1) else TreeCheck(true, "запись возможна", free)
    }

    // ------------------------------------------------------------------ export
    class ExportResult(
        val runDocId: String?,
        val runName: String,
        val total: Int,
        val copied: Int,
        val bytes: Long,
        val failures: List<String>,
        val cancelled: Boolean,
    ) {
        val complete: Boolean get() = failures.isEmpty() && !cancelled && runDocId != null
    }

    /**
     * Copies a finished run folder into <tree>/android_dump/<run name>. summary.json is not copied here: the caller writes it last, once it
     * knows whether every other file arrived.
     */
    fun exportRun(
        ctx: Context,
        srcRun: File,
        tree: Uri,
        cancel: AtomicBoolean,
        progress: (done: Int, total: Int, file: String) -> Unit,
    ): ExportResult {
        val rootId = DocumentsContract.getTreeDocumentId(tree)
        val dumpId = ensureDir(ctx, tree, rootId, "android_dump")
            ?: return ExportResult(null, srcRun.name, 0, 0, 0, listOf("не удалось создать каталог android_dump в выбранной папке"), false)
        val taken = children(ctx, tree, dumpId).map { it.name }.toSet()
        var runName = srcRun.name
        var n = 1
        while (runName in taken) {
            runName = "${srcRun.name}_$n"
            n++
        }
        val runId = createDir(ctx, tree, dumpId, runName)
            ?: return ExportResult(null, runName, 0, 0, 0, listOf("не удалось создать каталог запуска $runName"), false)

        val failures = ArrayList<String>()
        val files = ArrayList<File>()
        val dirs = ArrayList<File>()
        srcRun.walkTopDown().forEach {
            if (it == srcRun) return@forEach
            if (it.isDirectory) dirs.add(it)
            else if (it.isFile && !(it.parentFile == srcRun && it.name == "summary.json")) files.add(it)
        }
        val dirIds = HashMap<String, String>()
        dirIds[""] = runId

        fun dirFor(rel: String): String? {
            if (rel.isEmpty()) return runId
            dirIds[rel]?.let { return it }
            val parent = dirFor(rel.substringBeforeLast('/', "")) ?: return null
            val id = ensureDir(ctx, tree, parent, rel.substringAfterLast('/')) ?: return null
            dirIds[rel] = id
            return id
        }

        // Empty folders (for example "metadata") are part of the layout too.
        for (d in dirs) {
            val rel = d.relativeTo(srcRun).path
            if (dirFor(rel) == null) failures.add("папка $rel не создана")
        }
        var copied = 0
        var bytes = 0L
        val buf = ByteArray(256 * 1024)
        for ((i, f) in files.withIndex()) {
            if (cancel.get()) return ExportResult(runId, runName, files.size, copied, bytes, failures, true)
            val rel = f.relativeTo(srcRun).path
            progress(i, files.size, rel)
            val parent = dirFor(rel.substringBeforeLast('/', ""))
            if (parent == null) {
                failures.add("$rel: нет папки назначения")
                continue
            }
            try {
                val doc = DocumentsContract.createDocument(ctx.contentResolver, docUri(tree, parent), BIN, f.name)
                if (doc == null) {
                    failures.add("$rel: файл не создан")
                    continue
                }
                val out = ctx.contentResolver.openOutputStream(doc, "w")
                if (out == null) {
                    failures.add("$rel: не удалось открыть файл для записи")
                    continue
                }
                var written = 0L
                out.use { o ->
                    FileInputStream(f).use { inp ->
                        while (true) {
                            val r = inp.read(buf)
                            if (r < 0) break
                            o.write(buf, 0, r)
                            written += r
                        }
                    }
                }
                val sz = docSize(ctx, doc)
                if (written != f.length()) failures.add("$rel: записано $written из ${f.length()} байт")
                else if (sz >= 0 && sz != written) failures.add("$rel: на носителе $sz байт вместо $written")
                else {
                    copied++
                    bytes += written
                }
            } catch (e: Exception) {
                failures.add("$rel: ${e.message ?: e.javaClass.simpleName}")
            }
        }
        progress(files.size, files.size, "")
        return ExportResult(runId, runName, files.size, copied, bytes, failures, false)
    }

    fun docSize(ctx: Context, doc: Uri): Long = try {
        ctx.contentResolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_SIZE), null, null, null)?.use {
            if (it.moveToFirst() && !it.isNull(0)) it.getLong(0) else -1L
        } ?: -1L
    } catch (_: Exception) {
        -1L
    }

    /** Writes a text file into a folder. Returns an error text, or null on success. */
    fun writeText(ctx: Context, tree: Uri, parentDocId: String, name: String, text: String): String? {
        return try {
            val doc = DocumentsContract.createDocument(ctx.contentResolver, docUri(tree, parentDocId), BIN, name) ?: return "файл $name не создан"
            val out = ctx.contentResolver.openOutputStream(doc, "w") ?: return "не удалось открыть $name для записи"
            out.use { it.write(text.toByteArray(Charsets.UTF_8)) }
            null
        } catch (e: Exception) {
            "$name: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    /** Reads up to [maxBytes] of a text file. Returns the text and whether the file was longer, or null when it cannot be read. */
    fun readText(ctx: Context, uri: Uri, maxBytes: Int): Pair<String, Boolean>? = try {
        ctx.contentResolver.openInputStream(uri)?.use { s ->
            val buf = ByteArray(maxBytes + 1)
            var n = 0
            while (n < buf.size) {
                val r = s.read(buf, n, buf.size - n)
                if (r < 0) break
                n += r
            }
            String(buf, 0, minOf(n, maxBytes), Charsets.UTF_8) to (n > maxBytes)
        }
    } catch (_: Exception) {
        null
    }

    fun readAll(ctx: Context, uri: Uri, maxBytes: Int = 1 shl 20): String? = readText(ctx, uri, maxBytes)?.first
}
