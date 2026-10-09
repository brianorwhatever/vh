import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    application
}

group = "org.vhlog"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

application {
    applicationName = "vh-log-driver"
    mainClass.set("org.vhlog.driver.DriverKt")
    // The driver is short-lived and single-threaded; favour startup time.
    applicationDefaultJvmArgs = listOf("-XX:+UseSerialGC", "-Xss16m")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("vhlog.vectors", rootDir.resolve("../../vectors").absolutePath)
    jvmArgs("-Xss16m")
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
