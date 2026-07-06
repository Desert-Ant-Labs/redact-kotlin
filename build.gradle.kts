import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.21"
    kotlin("plugin.serialization") version "2.1.21"
    `java-library`
    `maven-publish`
}

group = "ai.desertant"
version = "0.2.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    // ONNX Runtime (desktop JVM). On Android, exclude this and add
    // `com.microsoft.onnxruntime:onnxruntime-android` instead - the Java API
    // (OrtEnvironment / OrtSession / OnnxTensor) is identical, so the SDK code
    // is unchanged.
    api("com.microsoft.onnxruntime:onnxruntime:1.20.0")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

tasks.test {
    useJUnitPlatform()
    maxHeapSize = "2g"
}

// Published via JitPack, which runs `publishToMavenLocal` against a git tag.
// Consumers resolve it as `com.github.Desert-Ant-Labs:redact-kotlin:<tag>`.
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "redact"

            pom {
                name.set("Redact")
                description.set("On-device multilingual PII redaction for JVM and Android: names, addresses, emails, cards, IBANs, national IDs, VAT numbers and more across 24 EU languages.")
                url.set("https://github.com/Desert-Ant-Labs/redact-kotlin")
                licenses {
                    license {
                        name.set("Desert Ant Labs Source-Available License v1.0")
                        url.set("https://github.com/Desert-Ant-Labs/redact-kotlin/blob/main/LICENSE.md")
                    }
                }
                scm {
                    url.set("https://github.com/Desert-Ant-Labs/redact-kotlin")
                    connection.set("scm:git:https://github.com/Desert-Ant-Labs/redact-kotlin.git")
                }
            }
        }
    }
}
