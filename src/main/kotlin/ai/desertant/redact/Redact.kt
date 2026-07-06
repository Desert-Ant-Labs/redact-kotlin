package ai.desertant.redact

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A single detected entity and the placeholder that stands in for it. */
data class RedactionItem(
    /** PII category, e.g. `"EMAIL"`. */
    val label: String,
    /** The original (sensitive) text that was matched. */
    val original: String,
    /** The unique, restorable placeholder, e.g. `"[EMAIL_1]"`. */
    val placeholder: String,
    /** Confidence in `0.0..1.0` (deterministic recognizers report `1.0`). */
    val confidence: Double,
    /** Start offset of [original] in the source text (UTF-16). */
    val start: Int,
    /** End offset (exclusive). */
    val end: Int,
)

/** A detected PII span (from [Redact.detect]). */
data class Detection(val start: Int, val end: Int, val label: String)

/**
 * A redaction: text with unique placeholders, the detections, and the mapping
 * needed to restore the originals after out-of-band processing (e.g. an LLM).
 */
data class Redaction(
    /** The input with each entity replaced by its `[LABEL_N]` placeholder. */
    val redactedText: String,
    /** Every detected entity, in document order. */
    val items: List<RedactionItem>,
) {
    /** Fill the originals back into [processed] by substituting each placeholder. */
    fun restore(processed: String): String {
        var out = processed
        for (item in items) out = out.replace(item.placeholder, item.original)
        return out
    }
}

/** Options controlling detection and redaction. */
data class Options(
    /** Minimum confidence for neural detections. Structured recognizers always
     * apply. Default `0.6`. */
    val minimumConfidence: Double = 0.6,
    /** If set, only these categories are detected/redacted; otherwise all are. */
    val labels: Set<String>? = null,
)

/** Thrown when a bundled model resource cannot be found or loaded. */
class RedactException(message: String) : Exception(message)

/**
 * On-device, multilingual PII redaction.
 *
 * Finds names, addresses, emails, phone numbers, cards, IBANs, national IDs, VAT
 * numbers and more across the 24 official EU languages, fully on device. A tiny
 * bundled ONNX token classifier plus a dependency-free deterministic recognizer
 * layer. The model loads once on first use.
 *
 * ```kotlin
 * val r = Redact.redaction("Email Anna at anna@example.com.")
 * r.redactedText            // "Email [GIVEN_NAME_1] at [EMAIL_1]."
 * r.items.first().original  // "Anna"
 * ```
 */
object Redact {
    private val KNOWN = setOf(
        "GIVEN_NAME", "SURNAME", "STREET_NAME", "BUILDING_NUMBER", "SECONDARY_ADDRESS",
        "CITY", "STATE", "ZIP_CODE", "EMAIL", "PHONE", "CREDIT_CARD", "BANK_ACCOUNT",
        "ROUTING_NUMBER", "IP_ADDRESS", "URL", "GOVERNMENT_ID", "PASSPORT",
        "DRIVERS_LICENSE", "TAX_ID", "SSN", "IMEI",
    )

    /**
     * Detect and redact the PII in [text]. Each entity is replaced by a unique,
     * numbered placeholder (`[EMAIL_1]`, `[GIVEN_NAME_1]`, ...) so the result is
     * safe to hand to an LLM and restore afterwards via [Redaction.restore].
     *
     * Suspends on a background dispatcher, loading the model lazily on first call.
     */
    suspend fun redaction(text: String, options: Options = Options()): Redaction =
        withContext(Dispatchers.Default) { redactBlocking(text, options) }

    /** Detect PII spans in [text] without building placeholders. */
    suspend fun detect(text: String, options: Options = Options()): List<Detection> =
        withContext(Dispatchers.Default) {
            model.detect(text, options.minimumConfidence, options.labels).map { Detection(it.start, it.end, it.label) }
        }

    private fun redactBlocking(text: String, options: Options): Redaction {
        val spans = model.detect(text, options.minimumConfidence, options.labels)
            .sortedWith(compareBy({ it.start }, { it.end }))
        val counts = HashMap<String, Int>()
        val items = ArrayList<RedactionItem>()
        val out = StringBuilder()
        var last = 0
        for (span in spans) {
            if (span.label !in KNOWN) continue
            val s = span.start; val e = span.end
            if (s < last || s >= e || e > text.length) continue
            val n = (counts[span.label] ?: 0) + 1
            counts[span.label] = n
            val placeholder = "[${span.label}_$n]"
            items.add(RedactionItem(span.label, text.substring(s, e), placeholder, span.score, s, e))
            out.append(text, last, s).append(placeholder)
            last = e
        }
        out.append(text, last, text.length)
        return Redaction(out.toString(), items)
    }

    private val model: Model by lazy {
        Model(
            onnx = resource("redact.onnx"),
            tokenizerBytes = resource("redact_tokenizer.bin"),
            labelsJson = resource("labels.json").toString(Charsets.UTF_8),
        )
    }

    private fun resource(name: String): ByteArray =
        (Redact::class.java.getResourceAsStream("/$name")
            ?: throw RedactException("Redact resource not found in package: $name"))
            .use { it.readBytes() }
}
