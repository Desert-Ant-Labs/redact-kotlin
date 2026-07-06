package ai.desertant.redact

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.LongBuffer
import kotlin.math.exp

/**
 * The neural token classifier (ONNX Runtime) reconciled with the deterministic
 * recognizer layer via the shared pipeline. Holds a process-wide ONNX session;
 * construct once (via [Redact]) and reuse.
 */
internal class Model(onnx: ByteArray, tokenizerBytes: ByteArray, labelsJson: String) {
    private val tokenizer = Tokenizer.fromBytes(tokenizerBytes)
    private val id2label: Array<String>
    private val env: OrtEnvironment = OrtEnvironment.getEnvironment()
    private val session: OrtSession

    init {
        val root = Json.parseToJsonElement(labelsJson).jsonObject
        val obj = root["id2label"]?.jsonObject ?: root
        val n = obj.size
        val arr = Array(n) { "O" }
        for ((k, v) in obj) arr[k.toInt()] = v.jsonPrimitive.content
        id2label = arr
        session = env.createSession(onnx, OrtSession.SessionOptions())
    }

    private fun reconstructOffsets(text: String, pieces: List<String>): List<IntArray> {
        var cursor = 0
        val out = ArrayList<IntArray>(pieces.size)
        for (piece in pieces) {
            val core = piece.removePrefix(Tokenizer.METASPACE)
            if (core.isEmpty()) { out.add(intArrayOf(cursor, cursor)); continue }
            val idx = text.indexOf(core, cursor)
            if (idx < 0) { out.add(intArrayOf(cursor, cursor)); continue }
            out.add(intArrayOf(idx, idx + core.length)); cursor = idx + core.length
        }
        return out
    }

    private fun mlSpans(text: String, minScore: Double): List<Span> {
        var content = tokenizer.tokenize(text)
        if (content.size > MAX_LENGTH - 2) content = content.subList(0, MAX_LENGTH - 2)
        val t = content.size + 2
        val ids = LongArray(t)
        ids[0] = tokenizer.bosId.toLong()
        for (i in content.indices) ids[i + 1] = content[i].id.toLong()
        ids[t - 1] = tokenizer.eosId.toLong()
        val mask = LongArray(t) { 1L }

        val shape = longArrayOf(1, t.toLong())
        val logits: FloatArray
        OnnxTensor.createTensor(env, LongBuffer.wrap(ids), shape).use { idsT ->
            OnnxTensor.createTensor(env, LongBuffer.wrap(mask), shape).use { maskT ->
                session.run(mapOf("input_ids" to idsT, "attention_mask" to maskT)).use { res ->
                    val fb = (res[0] as OnnxTensor).floatBuffer
                    logits = FloatArray(fb.remaining()); fb.get(logits)
                }
            }
        }
        val c = logits.size / t

        val bestId = IntArray(t); val bestProb = DoubleArray(t)
        for (i in 0 until t) {
            var mx = Float.NEGATIVE_INFINITY
            for (j in 0 until c) { val v = logits[i * c + j]; if (v > mx) mx = v }
            var sum = 0.0; var top = 0; var tv = Float.NEGATIVE_INFINITY
            for (j in 0 until c) { sum += exp((logits[i * c + j] - mx).toDouble()); if (logits[i * c + j] > tv) { tv = logits[i * c + j]; top = j } }
            bestId[i] = top; bestProb[i] = exp((tv - mx).toDouble()) / sum
        }

        val pieceOffsets = reconstructOffsets(text, content.map { it.text })
        val offsets = ArrayList<IntArray>(t)
        offsets.add(intArrayOf(0, 0))
        offsets.addAll(pieceOffsets)
        offsets.add(intArrayOf(0, 0))

        val low = minOf(LOW_SCORE, minScore)
        val tags = (0 until t).map { if (bestProb[it] >= low) id2label[bestId[it]] else "O" }
        val scored = ArrayList<Pair<Span, Double>>()
        for (span in Pipeline.bioesToSpans(tags, offsets)) {
            var mx = 0.0
            for (i in 0 until t) { val a = offsets[i][0]; val b = offsets[i][1]; if (b > a && maxOf(a, span.start) < minOf(b, span.end)) mx = maxOf(mx, bestProb[i]) }
            scored.add(span to mx)
        }
        var kept = Pipeline.hysteresis(text, scored, minScore)
        kept = Pipeline.mergeSpansPriority(kept)
        kept = Pipeline.attachBuildingNumbers(text, Pipeline.extendParticleNames(text, Pipeline.bridgeNameGaps(text, Pipeline.snapSpans(text, kept))))
        kept = Pipeline.redactSecondaryAddress(text, Pipeline.attachStateCodes(text, Pipeline.redactUsStreet(text, kept)))
        return Pipeline.mergeSpansPriority(kept)
    }

    fun detect(text: String, minScore: Double, labels: Set<String>?): List<Span> {
        val det = Deterministic.detect(text, Deterministic.owned)
        val ml = mlSpans(Pipeline.maskText(text, det), minScore)
        val corr = Deterministic.detect(text, setOf("PHONE")).filter { it.label !in Deterministic.owned }
        var spans = Pipeline.cleanSpans(text, Pipeline.relabelByContext(text, Pipeline.resolve(det + corr, ml)))
        if (labels != null) spans = spans.filter { it.label in labels }
        return spans
    }

    companion object {
        const val MIN_SCORE = 0.6
        const val LOW_SCORE = 0.3
        const val MAX_LENGTH = 256
    }
}
