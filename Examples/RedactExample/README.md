# Redact example (JVM)

A tiny console demo of on-device PII redaction with
[`ai.desertant:redact`](https://github.com/Desert-Ant-Labs/redact-kotlin).

```bash
./gradlew run                              # built-in sample
./gradlew run --args="Call +49 30 1234567" # your own text
```

It uses a composite build (`includeBuild("../..")`) to pull the library from this
repo, so there is nothing to publish first.
