package com.mlmvpn.scanner.importer

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

// Kotlin port of the module framework from FrontierTM/Pantegnos (AGPL-3.0).
// See NOTICE-Pantegnos.md in the repo root for attribution.

class ImportRequest(
    val fileName: String,
    val data: ByteArray,
    val proto: String,      // URI scheme without "://", or ""
    val payload: String,    // text after "://", or the whole text
    val password: String? = null,
)

/**
 * @param links share links found in the decrypted text, ready for the Xray node importer
 * @param blockedReason set when the creator locked the config (expired, device-locked); do not import
 */
class ImportResult(
    val text: String,
    val fileName: String,
    val links: List<String> = emptyList(),
    val blockedReason: String? = null,
)

class DecryptException(message: String, cause: Throwable? = null) : Exception(message, cause)

interface ConfigDecryptor {
    val name: String
    val extension: String                           // e.g. ".v2box"
    val schemes: List<String> get() = emptyList()   // e.g. "v2box"
    fun needsPassword(proto: String, payload: String): Boolean = false
    fun decrypt(req: ImportRequest): ImportResult
}

object DecryptorRegistry {
    private val all: List<ConfigDecryptor> = listOf(V2BoxDecryptor)

    fun find(fileName: String, proto: String): ConfigDecryptor? {
        val dot = fileName.lastIndexOf('.')
        val ext = if (dot >= 0) fileName.substring(dot).lowercase() else ""
        if (ext.isNotEmpty()) all.firstOrNull { it.extension == ext }?.let { return it }
        return all.firstOrNull { d -> d.schemes.any { matchScheme(it, proto) } }
    }

    fun lookup(fileName: String, content: String): Triple<ConfigDecryptor?, String, String> {
        val (proto, payload) = splitContent(content)
        return Triple(find(fileName, proto), proto, payload)
    }

    fun splitContent(content: String): Pair<String, String> {
        var start = 0
        while (start < content.length && content[start].isWhitespace()) start++
        for (i in start until content.length) {
            val c = content[i]
            if (c == ':') {
                return if (i > start && content.startsWith("://", i))
                    content.substring(start, i) to content.substring(i + 3)
                else "" to content
            }
            if (!isSchemeChar(c)) return "" to content
        }
        return "" to content
    }

    private fun isSchemeChar(c: Char) =
        c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '+' || c == '-' || c == '.'

    private fun matchScheme(pattern: String, proto: String): Boolean =
        if (pattern.endsWith("*")) proto.startsWith(pattern.dropLast(1)) else pattern == proto
}

/** Finds Xray-importable share links inside decrypted JSON/text. */
object LinkExtractor {
    private val schemes = listOf("vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "tuic", "socks")

    fun isLink(s: String) = schemes.any { s.startsWith("$it://", ignoreCase = true) }

    fun fromText(text: String): List<String> {
        val parsed = runCatching { JSONTokener(text.trim()).nextValue() }.getOrNull()
        val out = mutableListOf<String>()
        if (parsed is JSONObject || parsed is JSONArray) walk(parsed, out)
        else text.lines().map { it.trim() }.filter(::isLink).forEach(out::add)
        return out.distinct()
    }

    private fun walk(node: Any?, out: MutableList<String>) {
        when (node) {
            is JSONObject -> node.keys().forEach { walk(node.opt(it), out) }
            is JSONArray -> for (i in 0 until node.length()) walk(node.opt(i), out)
            is String -> node.lines().map { it.trim() }.filter(::isLink).forEach(out::add)
        }
    }
}
