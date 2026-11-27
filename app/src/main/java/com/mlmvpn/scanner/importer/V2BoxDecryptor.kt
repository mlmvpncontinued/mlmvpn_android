package com.mlmvpn.scanner.importer

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// Port of Pantegnos v2box.go (AGPL-3.0). See NOTICE-Pantegnos.md.
object V2BoxDecryptor : ConfigDecryptor {
    override val name = "V2Box export / locked profile"
    override val extension = ".v2box"
    override val schemes = listOf("v2box")

    private const val MAGIC = "v2box_export"
    private const val STATIC_KEY = "V2BoxEncryptionKey2026_Secret!#%"
    private const val LOCKED = "locked="

    override fun needsPassword(proto: String, payload: String) =
        parse(payload)?.optBoolean("isPasswordProtected") == true

    override fun decrypt(req: ImportRequest): ImportResult {
        val text = when {
            req.proto.equals("v2box", true) -> "v2box://" + req.payload
            req.data.isNotEmpty() -> String(req.data, Charsets.UTF_8)
            else -> req.payload
        }.trim()
        val outName = req.fileName.removeSuffix(".txt").substringBeforeLast('.') + ".txt"

        if (text.startsWith("v2box://", true)) {
            val body = text.substring(8)
            if (!body.startsWith(LOCKED))
                throw DecryptException("This is an install link, not a profile export; open the file it points to.")
            val plain = String(b64(body.removePrefix(LOCKED)), Charsets.UTF_8)
            val lines = plain.lines().map { it.trim() }.filter { it.isNotEmpty() }
            return ImportResult(
                text = lines.joinToString("\n"),
                fileName = outName,
                links = lines.filter(LinkExtractor::isLink),
                blockedReason = "Locked profile link: V2Box accepts it only on the devices its creator allowed.",
            )
        }

        val exp = parse(text) ?: throw DecryptException("Not a .v2box export")
        val protected = exp.optBoolean("isPasswordProtected")
        val key = if (protected) {
            val pw = req.password?.takeIf { it.isNotEmpty() } ?: throw DecryptException("This export is password protected")
            MessageDigest.getInstance("SHA-256").digest(pw.toByteArray())
        } else STATIC_KEY.toByteArray()

        val nonce = b64(exp.getString("nonce"))
        val tag = b64(exp.getString("tag"))
        val cipherText = b64(exp.getString("ciphertext"))
        if (nonce.size != 12 || tag.size != 16 || cipherText.isEmpty()) throw DecryptException("Malformed export")

        val plain = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                doFinal(cipherText + tag)
            }
        } catch (e: Exception) {
            throw DecryptException(if (protected) "Incorrect password or corrupted export" else "Decryption failed (corrupted export)", e)
        }

        val expires = if (exp.isNull("expirationTimestamp")) null else exp.optDouble("expirationTimestamp")
        val devices = exp.optJSONArray("allowedDeviceIDs")?.length() ?: 0
        val expired = expires != null && System.currentTimeMillis() > (expires * 1000).toLong()
        val reason = when {
            expired -> "This export has expired."
            devices > 0 -> "This export is locked to specific devices by its creator."
            else -> null
        }
        val payload = String(plain, Charsets.UTF_8)
        val pretty = runCatching { JSONObject(payload).toString(2) }.getOrDefault(payload)
        val header = "// V2Box export v${exp.optInt("version")}, password: ${if (protected) "required" else "no"}, " +
            "device lock: ${if (devices > 0) devices else "none"}\n\n"
        // links come from the raw payload, not the pretty-printed copy (org.json escapes "/" as "\/")
        return ImportResult(header + pretty, outName, LinkExtractor.fromText(payload), reason)
    }

    private fun parse(s: String): JSONObject? = runCatching {
        JSONObject(s.trim()).takeIf {
            it.optString("magic") == MAGIC && it.has("ciphertext") && it.has("nonce") && it.has("tag")
        }
    }.getOrNull()

    // android.util.Base64 (minSdk 24 has no java.util.Base64); tolerant of padding and URL-safe alphabets
    private fun b64(v: String): ByteArray {
        val c = v.trim().trimEnd('=')
        return try { Base64.decode(c, Base64.DEFAULT) } catch (_: IllegalArgumentException) { Base64.decode(c, Base64.URL_SAFE) }
    }
}
