package ai.desertant.redact

import java.text.Normalizer

/**
 * XLM-R SentencePiece Unigram tokenizer, a pure-Kotlin port of the Swift
 * implementation (NFKC normalization, no lowercasing, U+2581 metaspace, Viterbi
 * over the vocab with a `min_score - 10` unknown penalty). Backed by the compact
 * `redact_tokenizer.bin` (RDTK format).
 */
internal class Tokenizer private constructor(
    val bosId: Int,
    val eosId: Int,
    val unkId: Int,
    private val scores: FloatArray,
    private val index: HashMap<String, Int>,
    private val unkPenalty: Double,
    private val maxLen: Int,
) {
    /** One content sub-word: its vocab [id] and its surface [text]. */
    data class Token(val id: Int, val text: String)

    /** Tokenize [text] into content sub-words (no BOS/EOS), Viterbi-optimal over the vocab. */
    fun tokenize(text: String): List<Token> {
        val normalized = METASPACE + Normalizer.normalize(text, Normalizer.Form.NFKC).replace(" ", METASPACE)
        val cp = normalized.codePoints().toArray()
        val n = cp.size
        if (n == 0) return emptyList()

        val neg = -1e18
        val best = DoubleArray(n + 1) { if (it == 0) 0.0 else neg }
        val backPos = IntArray(n + 1) { -1 }
        val backId = IntArray(n + 1) { -1 }
        for (i in 1..n) {
            val lo = maxOf(0, i - maxLen)
            for (j in lo until i) {
                val tid = index[String(cp, j, i - j)] ?: continue
                val sc = best[j] + scores[tid]
                if (sc > best[i]) { best[i] = sc; backPos[i] = j; backId[i] = tid }
            }
            val cand = best[i - 1] + unkPenalty
            if (cand > best[i]) { best[i] = cand; backPos[i] = i - 1; backId[i] = unkId }
        }

        val tokens = ArrayList<Token>()
        var i = n
        while (i > 0) {
            val j = backPos[i]
            tokens.add(Token(backId[i], String(cp, j, i - j)))
            i = j
        }
        tokens.reverse()
        return tokens
    }

    companion object {
        const val METASPACE = "\u2581"

        fun fromBytes(b: ByteArray): Tokenizer {
            require(b.size >= 21 && b[0].toInt() == 0x52 && b[1].toInt() == 0x44 &&
                b[2].toInt() == 0x54 && b[3].toInt() == 0x4B) { "redact: bad tokenizer file" }
            var off = 5
            fun i32(): Int {
                val v = (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or
                    ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)
                off += 4
                return v
            }
            val unkId = i32(); val bosId = i32(); val eosId = i32()
            val count = i32()
            require(count > 0) { "redact: empty tokenizer vocab" }

            val scores = FloatArray(count) { Float.fromBits(i32()) }
            val lens = IntArray(count) {
                val v = (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8)
                off += 2
                v
            }
            val index = HashMap<String, Int>(count * 2)
            var maxScalars = 1
            for (k in 0 until count) {
                val piece = String(b, off, lens[k], Charsets.UTF_8)
                off += lens[k]
                index[piece] = k
                val ns = piece.codePointCount(0, piece.length)
                if (ns > maxScalars) maxScalars = ns
            }
            var minScore = Float.MAX_VALUE
            for (s in scores) if (s < minScore) minScore = s
            return Tokenizer(bosId, eosId, unkId, scores, index, minScore.toDouble() - 10.0,
                minOf(maxScalars, 32))
        }
    }
}
