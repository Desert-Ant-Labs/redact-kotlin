plugins {
    kotlin("jvm") version "2.1.21"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("ai.desertant:redact")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}

application { mainClass.set("MainKt") }
kotlin { jvmToolchain(17) }
