import ai.desertant.redact.Redact
import kotlinx.coroutines.runBlocking

// Minimal console demo of on-device PII redaction with ai.desertant:redact.
// Pass text as arguments, or run with no args for a built-in sample.
//   ./gradlew run --args="Email me at a@b.com"
fun main(args: Array<String>) = runBlocking {
    val text = if (args.isNotEmpty()) args.joinToString(" ") else
        "Email Anna Kovács at anna@example.hu, IBAN DE89370400440532013000. " +
        "Ship to 123 Main Street, Apt 4B. VAT DE129273398, IMEI 490154203237518."

    val r = Redact.redaction(text)
    println("input:    $text")
    println("redacted: ${r.redactedText}")
    println("items:")
    for (i in r.items) println("  ${i.placeholder} = \"${i.original}\"  (${i.label})")
}
