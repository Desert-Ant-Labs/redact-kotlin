package ai.desertant.redact

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RedactTest {
    private fun res(name: String) =
        RedactTest::class.java.getResourceAsStream("/$name")!!.readBytes().toString(Charsets.UTF_8)

    private fun detLabels(text: String): Set<String> =
        Deterministic.detect(text).map { "${text.substring(it.start, it.end)}:${it.label}" }.toSet()

    // ---- deterministic layer (no model) ----
    @Test fun deterministicRecognizers() {
        val l = detLabels("Email me@x.com, IBAN DE89370400440532013000, card 4111111111111111.")
        assertTrue("me@x.com:EMAIL" in l)
        assertTrue("DE89370400440532013000:BANK_ACCOUNT" in l)
    }

    @Test fun euIdentifiers() {
        assertTrue("DE129273398:TAX_ID" in detLabels("Our VAT is DE129273398 for the invoice."))
        assertTrue("490154203237518:IMEI" in detLabels("IMEI 490154203237518 was blocked."))
        assertTrue("05123/03/1234567:DRIVERS_LICENSE" in detLabels("Prawo jazdy 05123/03/1234567."))
        assertTrue("111222333:GOVERNMENT_ID" in detLabels("Mijn BSN is 111222333 graag."))
        assertTrue("DE111111111:TAX_ID" !in detLabels("ref DE111111111 here"))
    }

    // ---- deterministic parity vs Python (412 texts) ----
    private val jsLabels = setOf("EMAIL","URL","IP_ADDRESS","CREDIT_CARD","BANK_ACCOUNT","GOVERNMENT_ID","TAX_ID","PASSPORT","DRIVERS_LICENSE","IMEI","SSN","ROUTING_NUMBER","PHONE")
    private fun key(spans: List<Triple<Int, Int, String>>) = spans.map { "${it.first},${it.second},${it.third}" }.toSortedSet().joinToString("|")

    @Test fun deterministicParity() {
        val corpus = Json.parseToJsonElement(res("deterministic_corpus.json")).jsonArray
        var ok = 0
        for (row in corpus) {
            val o = row.jsonObject
            val text = o.getValue("text").jsonPrimitive.content
            val py = o.getValue("py").jsonArray.map { val a = it.jsonArray; Triple(a[0].jsonPrimitive.int, a[1].jsonPrimitive.int, a[2].jsonPrimitive.content) }
            val kt = Deterministic.detect(text, jsLabels).map { Triple(it.start, it.end, it.label) }
            if (key(py) == key(kt)) ok++
        }
        assertEquals(corpus.size, ok, "deterministic parity mismatches")
    }

    // ---- pipeline parity vs Python (post-model chain) ----
    private fun spans(a: kotlinx.serialization.json.JsonArray) = a.map { val t = it.jsonArray; Span(t[0].jsonPrimitive.int, t[1].jsonPrimitive.int, t[2].jsonPrimitive.content) }

    @Test fun pipelineParity() {
        val corpus = Json.parseToJsonElement(res("pipeline_corpus.json")).jsonArray
        var ok = 0
        for (row in corpus) {
            val o = row.jsonObject
            val text = o.getValue("text").jsonPrimitive.content
            var ml = spans(o.getValue("ml").jsonArray)
            val det = spans(o.getValue("det").jsonArray)
            ml = Pipeline.snapSpans(text, ml); ml = Pipeline.bridgeNameGaps(text, ml)
            ml = Pipeline.extendParticleNames(text, ml); ml = Pipeline.attachBuildingNumbers(text, ml)
            ml = Pipeline.redactUsStreet(text, ml); ml = Pipeline.attachStateCodes(text, ml)
            ml = Pipeline.redactSecondaryAddress(text, ml)
            val out = Pipeline.cleanSpans(text, Pipeline.relabelByContext(text, Pipeline.resolve(det, ml)))
            val kt = out.map { Triple(it.start, it.end, it.label) }
            val py = o.getValue("py").jsonArray.map { val a = it.jsonArray; Triple(a[0].jsonPrimitive.int, a[1].jsonPrimitive.int, a[2].jsonPrimitive.content) }
            if (key(py) == key(kt)) ok++
        }
        assertEquals(corpus.size, ok, "pipeline parity mismatches")
    }

    // ---- full model pipeline ----
    @Test fun redactionEndToEnd() = runTest {
        val r = Redact.redaction("Email Anna Kovács at anna@example.hu, IBAN DE89370400440532013000.")
        assertTrue(Regex("""\[GIVEN_NAME_1\]""").containsMatchIn(r.redactedText), r.redactedText)
        assertTrue(Regex("""\[EMAIL_1\]""").containsMatchIn(r.redactedText))
        assertTrue(Regex("""\[BANK_ACCOUNT_1\]""").containsMatchIn(r.redactedText))
        assertEquals("anna@example.hu", r.items.first { it.label == "EMAIL" }.original)
    }

    @Test fun addressesVatImei() = runTest {
        val r = Redact.redaction("Ship to 123 Main Street, Apt 4B. VAT DE129273398, IMEI 490154203237518.")
        val got = r.items.map { it.label }.toSet()
        for (l in listOf("BUILDING_NUMBER", "STREET_NAME", "SECONDARY_ADDRESS", "TAX_ID", "IMEI"))
            assertTrue(l in got, "expected $l in $got")
    }

    @Test fun restoreRoundTrips() = runTest {
        val text = "Call Dr. Alice Grant on +49 30 1234567."
        val r = Redact.redaction(text)
        assertEquals(text, r.restore(r.redactedText))
    }
}
