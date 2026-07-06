package ai.desertant.redact

/** An internal detected span with UTF-16 character offsets into the source text
 * (matching the JS/Swift/Python reference pipelines so the ports agree exactly). */
internal data class Span(
    val start: Int,
    val end: Int,
    val label: String,
    val score: Double = 1.0,
)
