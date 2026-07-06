package ai.desertant.redact

/**
 * Span post-processing: BIOES decode, word snapping, name bridging/particles,
 * US address recognizers, the deterministic-owner merge, and final relabel/clean.
 * A faithful port of `redact_training.pipeline` (span-for-span parity with the
 * Python / JS / Swift runtimes).
 */
internal object Pipeline {
    private val NAME_FAMILIES = setOf("GIVEN_NAME", "SURNAME")
    private const val CONNECT = "-'\u2019"
    private val DET_OWNED = setOf("SSN", "CREDIT_CARD", "EMAIL", "URL", "IP_ADDRESS", "BANK_ACCOUNT", "ROUTING_NUMBER")

    private fun splitTag(t: String): Pair<String, String?> {
        if (t == "O") return "O" to null
        val i = t.indexOf('-')
        return t.substring(0, i) to t.substring(i + 1)
    }

    fun bioesToSpans(tags: List<String>, offsets: List<IntArray>): List<Span> {
        val out = ArrayList<Span>()
        var label: String? = null; var start = -1; var end = -1
        fun close() { if (label != null && start >= 0 && end > start) out.add(Span(start, end, label!!)); label = null; start = -1; end = -1 }
        for (i in tags.indices) {
            val (prefix, lab) = splitTag(tags[i])
            val a = offsets[i][0]; val b = offsets[i][1]
            if (b <= a) continue
            when (prefix) {
                "O" -> close()
                "S" -> { close(); out.add(Span(a, b, lab!!)) }
                "B" -> { close(); label = lab; start = a; end = b }
                "I" -> if (label == lab) end = b else { close(); label = lab; start = a; end = b }
                "E" -> if (label == lab) { end = b; close() } else { close(); out.add(Span(a, b, lab!!)) }
            }
        }
        close()
        return out
    }

    private fun isWordChar(c: Char): Boolean = c.isLetterOrDigit() || Character.getType(c).let {
        it == Character.NON_SPACING_MARK.toInt() || it == Character.COMBINING_SPACING_MARK.toInt() || it == Character.ENCLOSING_MARK.toInt()
    }

    private fun snapOne(text: String, s0: Int, e0: Int): IntArray {
        val n = text.length
        var s = maxOf(0, minOf(s0, n)); var e = maxOf(0, minOf(e0, n))
        while (s > 0) { val c = text[s - 1]; if (isWordChar(c)) s-- else if (CONNECT.contains(c) && s - 2 >= 0 && isWordChar(text[s - 2])) s-- else break }
        while (e < n) { val c = text[e]; if (isWordChar(c)) e++ else if (CONNECT.contains(c) && e + 1 < n && isWordChar(text[e + 1])) e++ else break }
        return intArrayOf(s, e)
    }

    private fun mergeSameLabel(spans: List<Span>): List<Span> {
        val ordered = spans.sortedWith(compareBy({ it.start }, { -(it.end - it.start) }, { it.label }))
        val out = ArrayList<Span>()
        for (s in ordered) {
            if (out.isNotEmpty() && s.label == out.last().label && s.start <= out.last().end)
                out[out.size - 1] = out.last().copy(end = maxOf(out.last().end, s.end))
            else if (out.isEmpty() || s.start >= out.last().end) out.add(s)
        }
        return out
    }

    fun snapSpans(text: String, spans: List<Span>): List<Span> = mergeSameLabel(spans.map {
        val r = snapOne(text, it.start, it.end); Span(r[0], r[1], it.label)
    })

    private val PARTICLES = setOf("de","del","della","dell","di","da","das","dos","du","van","von","der","den","ter","la","le","el","al","bin","ibn","mac","mc","o","st","of","y","e")
    private val ALL_PARTICLES = setOf("van","von","de","del","della","dell","di","da","das","dos","du","zu","af","ter","ten","des","do","der","den","la","le","el","y")
    private fun trimEdges(s: String) = s.trim('.', '\'', '\u2019', '-')
    private fun trimEndsNoDash(s: String) = s.trim('.', '\'', '\u2019')

    private fun gapIsNameLike(gap: String): Boolean {
        if (gap.isBlank()) return false
        if (gap.length > 20 || Regex("""[,;:/&|()\[\]{}"<>\n\t]""").containsMatchIn(gap)) return false
        for (tok in gap.split(Regex("""\s+"""))) {
            val w = trimEdges(tok)
            if (w.isEmpty()) continue
            if (w.lowercase() in PARTICLES || w.length == 1 || w[0] == w[0].uppercaseChar()) continue
            return false
        }
        return true
    }

    fun bridgeNameGaps(text: String, spans: List<Span>): List<Span> {
        val ordered = spans.sortedWith(compareBy({ it.start }, { it.end }))
        val out = ArrayList<Span>()
        for (s in ordered) {
            val p = out.lastOrNull()
            if (p != null && p.label in NAME_FAMILIES && s.label in NAME_FAMILIES && s.start >= p.end && gapIsNameLike(text.substring(p.end, s.start)))
                out[out.size - 1] = p.copy(end = maxOf(p.end, s.end))
            else out.add(s)
        }
        return out
    }

    private val NEXT_RE = Regex("""^(\s+)([^\s,.;:!?)\]}"]+)""")
    fun extendParticleNames(text: String, spans: List<Span>): List<Span> {
        val ordered = spans.sortedWith(compareBy({ it.start }, { it.end }))
        val out = ArrayList<Span>()
        for (sp0 in ordered) {
            var sp = sp0
            if (sp.label in NAME_FAMILIES) {
                val tw = Regex("""([^\s]+)\s*$""").find(text.substring(sp.start, sp.end))
                var consumed = tw != null && trimEndsNoDash(tw.groupValues[1]).lowercase() in ALL_PARTICLES
                var pos = sp.end
                while (true) {
                    val mm = NEXT_RE.find(text.substring(pos)) ?: break
                    val tok = mm.groupValues[2]
                    if (trimEndsNoDash(tok).lowercase() in ALL_PARTICLES) { pos += mm.value.length; consumed = true; continue }
                    if (consumed && tok[0] == tok[0].uppercaseChar() && tok[0] != tok[0].lowercaseChar()) pos += mm.value.length
                    break
                }
                if (pos > sp.end) sp = sp.copy(end = pos)
            }
            out.add(sp)
        }
        return mergeSameLabel(out)
    }

    private val BNUM_AFTER = Regex("""^[\s,]{0,2}(\d{1,5}[a-zA-Z]?(?:[-/]\d{1,4}[a-zA-Z]?)?)\b""")
    private val BNUM_BEFORE = Regex("""(\d{1,5}[a-zA-Z]?)[\s,]{0,2}$""")
    fun attachBuildingNumbers(text: String, spans: List<Span>): List<Span> {
        val out = ArrayList(spans)
        val occ = spans.map { it.start to it.end }.toMutableList()
        fun free(a: Int, b: Int) = occ.none { it.first < b && a < it.second }
        for (s in spans) {
            if (s.label != "STREET_NAME") continue
            BNUM_AFTER.find(text.substring(s.end))?.let { mm ->
                val a = s.end + mm.range.first + mm.value.indexOf(mm.groupValues[1]); val b = a + mm.groupValues[1].length
                if (free(a, b)) { out.add(Span(a, b, "BUILDING_NUMBER")); occ.add(a to b) }
            }
            val base = maxOf(0, s.start - 8)
            BNUM_BEFORE.find(text.substring(base, s.start))?.let { mm ->
                val a = base + mm.range.first; val b = a + mm.groupValues[1].length
                if (free(a, b)) { out.add(Span(a, b, "BUILDING_NUMBER")); occ.add(a to b) }
            }
        }
        return mergeSameLabel(out).sortedWith(compareBy({ it.start }, { it.end }))
    }

    private val US_STREET_RE = Regex("""\b(\d{1,6}[A-Za-z]?)\s+((?:[A-Z][A-Za-z0-9.'’-]*\s+){0,4}(?:Street|Avenue|Boulevard|Road|Lane|Drive|Court|Place|Terrace|Circle|Highway|Parkway|Square|Trail|Crescent|Alley|Loop|Way|St|Ave|Blvd|Rd|Ln|Dr|Ct|Pl|Ter|Cir|Hwy|Pkwy|Sq|Trl|Aly))\b\.?(?=$|[\s,.;:)])""")
    private val STATE_ZIP_RE = Regex("""(?:,\s*|\s)([A-Z]{2})\s+(\d{5}(?:-\d{4})?)\b""")
    private val SEC_ADDR_RE = Regex("""\b(?:Apartment|Apt|Suite|Ste|Unit|Building|Bldg|Floor|Fl|Room|Rm|Department|Dept|Trailer|Trlr|Space|Spc|Lot)\.?\s*#?\s*(?:\d{1,4}[A-Za-z]?|[A-Za-z]\d{1,4})\b""", RegexOption.IGNORE_CASE)
    private val US_STATES = ("AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY").split(" ").toSet()

    fun redactUsStreet(text: String, spans: List<Span>): List<Span> {
        var out = ArrayList(spans)
        for (mm in US_STREET_RE.findAll(text)) {
            val bn = mm.groups[1]!!.range; val st = mm.groups[2]!!.range
            val bnS = bn.first; val bnE = bn.last + 1; val stS = st.first; val stE = st.last + 1
            out = ArrayList(out.filterNot { (it.label == "STREET_NAME" || it.label == "BUILDING_NUMBER") && maxOf(it.start, bnS) < minOf(it.end, stE) })
            out.add(Span(bnS, bnE, "BUILDING_NUMBER")); out.add(Span(stS, stE, "STREET_NAME"))
        }
        return mergeSameLabel(out).sortedWith(compareBy({ it.start }, { it.end }))
    }

    fun attachStateCodes(text: String, spans: List<Span>): List<Span> {
        val out = ArrayList(spans)
        val occ = out.map { it.start to it.end }.toMutableList()
        fun add(a: Int, b: Int, label: String) { if (occ.none { it.first < b && a < it.second }) { out.add(Span(a, b, label)); occ.add(a to b) } }
        for (mm in STATE_ZIP_RE.findAll(text)) {
            val sr = mm.groups[1]!!.range; val zr = mm.groups[2]!!.range
            if (text.substring(sr.first, sr.last + 1) in US_STATES) { add(sr.first, sr.last + 1, "STATE"); add(zr.first, zr.last + 1, "ZIP_CODE") }
        }
        return mergeSameLabel(out).sortedWith(compareBy({ it.start }, { it.end }))
    }

    fun redactSecondaryAddress(text: String, spans: List<Span>): List<Span> {
        var out = ArrayList(spans)
        for (mm in SEC_ADDR_RE.findAll(text)) {
            val s = mm.range.first; val e = mm.range.last + 1
            out = ArrayList(out.filterNot { (it.label == "SECONDARY_ADDRESS" || it.label == "BUILDING_NUMBER") && maxOf(it.start, s) < minOf(it.end, e) })
            out.add(Span(s, e, "SECONDARY_ADDRESS"))
        }
        return mergeSameLabel(out).sortedWith(compareBy({ it.start }, { it.end }))
    }

    private val ACCT_LEFT = Regex("""(?:\ba/?c\b|acct|account|konto|compte|cuenta|rekening|conta|\biban\b)\W{0,4}#?\s*$""", RegexOption.IGNORE_CASE)
    fun relabelByContext(text: String, spans: List<Span>): List<Span> = spans.map { s ->
        var lab = s.label
        val left = text.substring(maxOf(0, s.start - 28), s.start).lowercase()
        if (lab == "PHONE" && ACCT_LEFT.containsMatchIn(left)) lab = "BANK_ACCOUNT"
        else if (lab == "GOVERNMENT_ID" && ((left.contains("driv") && left.contains("licen")) || left.contains("führerschein") || left.contains("fuhrerschein") || left.contains("rijbewijs") || (left.contains("permis") && left.contains("conduire")))) lab = "DRIVERS_LICENSE"
        s.copy(label = lab)
    }

    private const val TRIM_TRAIL = " \t\n\r.,;:!?)]}\"\u00bb\u2019\u201d'"
    private const val TRIM_LEAD = " \t\n\r([{\"\u00ab\u2018\u201c"
    private val STRIP_TITLES = setOf("mr","mrs","ms","miss","mx","master","mstr","dr","prof","professor","doctor","dear","sir","madam","madame","monsieur","mme","mlle","herr","frau","fraulein","frl","mevrouw","dhr","signor","signora")
    fun cleanSpans(text: String, spans: List<Span>): List<Span> {
        val out = ArrayList<Span>()
        for (s in spans) {
            var st = s.start; var en = s.end
            while (en > st && TRIM_TRAIL.contains(text[en - 1])) en--
            while (st < en && TRIM_LEAD.contains(text[st])) st++
            if (s.label in NAME_FAMILIES) {
                while (st < en) {
                    val mm = Regex("""^(\S+)\s+""").find(text.substring(st, en)) ?: break
                    if (trimEndsNoDash(mm.groupValues[1]).lowercase() !in STRIP_TITLES) break
                    st += mm.value.length
                }
                val core = text.substring(st, en).trim('.', '\'', '\u2019', ' ')
                if (core.isEmpty() || core.lowercase() in STRIP_TITLES) continue
            }
            if (en > st) out.add(s.copy(start = st, end = en))
        }
        return out
    }

    private fun adjacentName(text: String, a: Span, b: Span): Boolean {
        val (lo, hi) = if (a.start <= b.start) a to b else b to a
        if (hi.start < lo.end) return true
        val gap = text.substring(lo.end, hi.start)
        return (gap.isBlank() && gap.length <= 3) || gapIsNameLike(gap)
    }

    fun hysteresis(text: String, scored: List<Pair<Span, Double>>, high: Double): List<Span> {
        val kept = ArrayList(scored.filter { it.second >= high }.map { it.first })
        val weak = ArrayList(scored.filter { it.second < high && it.first.label in NAME_FAMILIES }.map { it.first })
        var changed = true
        while (changed && weak.isNotEmpty()) {
            changed = false
            for (sp in ArrayList(weak)) {
                if (kept.any { it.label in NAME_FAMILIES && adjacentName(text, sp, it) }) {
                    kept.add(sp); weak.remove(sp); changed = true; break
                }
            }
        }
        return kept
    }

    fun mergeSpansPriority(spans: List<Span>): List<Span> {
        fun prio(s: Span) = intArrayOf(if (s.label in DET_OWNED) 2 else 1, s.end - s.start)
        fun gt(a: IntArray, b: IntArray) = a[0] > b[0] || (a[0] == b[0] && a[1] > b[1])
        val ordered = spans.sortedWith(compareBy({ it.start }, { -(it.end - it.start) }, { it.label }))
        val out = ArrayList<Span>()
        for (s in ordered) {
            if (out.isNotEmpty() && s.label == out.last().label && s.start <= out.last().end)
                out[out.size - 1] = out.last().copy(end = maxOf(out.last().end, s.end))
            else if (out.isEmpty() || s.start >= out.last().end) out.add(s)
            else if (gt(prio(s), prio(out.last()))) out[out.size - 1] = s
        }
        return out
    }

    fun resolve(detSpans: List<Span>, mlSpans: List<Span>): List<Span> {
        fun overlaps(a0: Int, a1: Int, b0: Int, b1: Int) = maxOf(a0, b0) < minOf(a1, b1)
        val suppressed = HashSet<Int>(); val keptMl = ArrayList<Span>()
        for (m in mlSpans) {
            var conflict = false
            for (i in detSpans.indices) {
                if (overlaps(m.start, m.end, detSpans[i].start, detSpans[i].end)) {
                    if (m.label == detSpans[i].label) suppressed.add(i) else conflict = true
                }
            }
            if (!conflict) keptMl.add(m)
        }
        val keptDet = detSpans.filterIndexed { i, _ -> i !in suppressed }
        return mergeSameLabel(keptDet + keptMl).sortedWith(compareBy({ it.start }, { it.end }, { it.label }))
    }

    fun maskText(text: String, spans: List<Span>): String {
        if (text.isEmpty()) return text
        val chars = text.toCharArray()
        for (s in spans) for (i in maxOf(0, s.start) until minOf(chars.size, s.end)) if (chars[i] != '\n') chars[i] = ' '
        return String(chars)
    }
}
