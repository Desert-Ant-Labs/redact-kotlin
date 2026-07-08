# Redact: On-device PII Redaction for Kotlin (Android, JVM)

On-device multilingual PII redaction for JVM and Android. Detects and masks
personal data (names, addresses, emails, phone numbers, cards, IBANs, national
IDs, VAT numbers and more) in text across **all 24 official EU languages** (Latin,
Greek and Cyrillic scripts). Everything runs on device; the text never leaves the
machine. Scrub PII from customer support records, LLM prompts, and application logs
so the raw data never reaches a server, yours or a third party's. Keep the
placeholder mapping and redaction is reversible pseudonymization
(restore the originals later); drop it and the masked text is permanently anonymized.

```kotlin
import ai.desertant.redact.Redact

val r = Redact.redaction("Email Anna Kovács at anna@example.hu.")
r.redactedText            // "Email [GIVEN_NAME_1] [SURNAME_1] at [EMAIL_1]."
r.items.first().original  // "Anna"
r.restore(r.redactedText) // back to the original
```

A tiny 6-layer ONNX token classifier handles contextual PII (names, streets,
messy natural-language data) while a dependency-free deterministic layer owns the
structured fields with real validation (Luhn cards, ISO-13616 IBANs, checksum-
validated national IDs for all 24 EU countries, all 27 EU VAT numbers, IMEI, and
per-country driving licences). It mirrors the Python training pipeline and the
Swift / JavaScript SDKs span-for-span.

## Install

Published via [JitPack](https://jitpack.io). Add the repository and dependency:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven("https://jitpack.io")
    }
}

// build.gradle.kts
dependencies {
    implementation("com.github.Desert-Ant-Labs:redact-kotlin:0.2.1")
}
```

The model (int4 ONNX, ~13.7 MB) and tokenizer are bundled in the artifact, so there is no
download at runtime. The library runs the model with
[ONNX Runtime](https://onnxruntime.ai). On **Android**, exclude the desktop
runtime and add the Android one instead - the Java API is identical:

```kotlin
implementation("com.github.Desert-Ant-Labs:redact-kotlin:0.2.1") {
    exclude(group = "com.microsoft.onnxruntime", module = "onnxruntime")
}
implementation("com.microsoft.onnxruntime:onnxruntime-android:1.20.0")
```

## Usage

`Redact` is a singleton; the model loads once on first call. All entry points are
`suspend` functions that run off the calling thread.

### Redact and restore (LLM round-trip)

Mask PII to unique placeholders, hand the placeholdered text to an LLM or any
external service, then fill the originals back in on-device.

```kotlin
val r = Redact.redaction(userText)
// r.redactedText: "Email [EMAIL_1] and [EMAIL_2] about [BANK_ACCOUNT_1]."

val reply = myLlm.rewrite(r.redactedText)   // sees only placeholders
val final = r.restore(reply)                 // originals filled back in
```

Placeholders are numbered per category (`[EMAIL_1]`, `[EMAIL_2]`, ...), so two
emails never collapse into one and restoration is order-independent. Instruct
your LLM to keep the `[LABEL_N]` tokens verbatim.

### Inspect detections

```kotlin
val r = Redact.redaction(text)
for (item in r.items) {
    println("${item.label} ${item.original} ${item.confidence} ${item.start}..${item.end}")
}
```

### Filter by category

```kotlin
val r = Redact.redaction(text, Options(labels = setOf("EMAIL", "PHONE", "CREDIT_CARD")))
```

### Just the spans

```kotlin
val spans = Redact.detect(text) // List<Detection>(start, end, label)
```

## API

```kotlin
object Redact {
    suspend fun redaction(text: String, options: Options = Options()): Redaction
    suspend fun detect(text: String, options: Options = Options()): List<Detection>
}

data class Options(
    val minimumConfidence: Double = 0.6,  // neural threshold; structured recognizers always apply
    val labels: Set<String>? = null,      // restrict categories; null = all
)

data class Redaction(val redactedText: String, val items: List<RedactionItem>) {
    fun restore(processed: String): String
}
// RedactionItem(label, original, placeholder, confidence, start, end)
```

## Categories

`GIVEN_NAME`, `SURNAME`, `STREET_NAME`, `BUILDING_NUMBER`, `SECONDARY_ADDRESS`,
`CITY`, `STATE`, `ZIP_CODE`, `EMAIL`, `PHONE`, `CREDIT_CARD`, `BANK_ACCOUNT`,
`ROUTING_NUMBER`, `IP_ADDRESS`, `URL`, `GOVERNMENT_ID`, `PASSPORT`,
`DRIVERS_LICENSE`, `TAX_ID`, `SSN`, and `IMEI` (deterministic-only).

## Requirements

JVM 11+ / Android API 24+. Depends on ONNX Runtime, kotlinx-coroutines, and
kotlinx-serialization.

## Other platforms

- **Swift (iOS/macOS/tvOS/visionOS):** [`redact-swift`](https://github.com/Desert-Ant-Labs/redact-swift)
- **Node / browser (JS/TS):** [`redact-js`](https://github.com/Desert-Ant-Labs/redact-js)
- **Model + weights + card:** [`desert-ant-labs/redact`](https://huggingface.co/desert-ant-labs/redact)

## License

[Desert Ant Labs Source-Available License](https://license.desertant.ai/1.0). Free
for most apps; a commercial license is required at scale. Full terms are in
[`LICENSE.md`](./LICENSE.md). Licensing: <licensing@desertant.ai>.
