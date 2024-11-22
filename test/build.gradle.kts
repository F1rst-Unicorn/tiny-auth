plugins {
    id("java")
}

repositories {
    mavenLocal()
    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
}

dependencies {
    testImplementation("com.google.guava:guava") {
        version {
            strictly("25.0-jre")
        }
    }
    testImplementation("com.google.code.gson:gson:2.10.1")
    testImplementation("org.apache.logging.log4j:log4j-api:2.13.3")
    testImplementation("org.apache.logging.log4j:log4j-core:2.20.0")
    testImplementation("org.apache.logging.log4j:log4j-web:2.13.3")
    testImplementation("org.apache.logging.log4j:log4j-slf4j-impl:2.13.3")
    testImplementation("commons-io:commons-io:2.7")
    testImplementation("io.burt:jmespath-core:0.5.0")
    testImplementation("io.burt:jmespath-gson:0.5.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.7.0")
    testImplementation("io.rest-assured:rest-assured:5.3.0")
    testImplementation("org.seleniumhq.selenium:selenium-java:3.141.59")
    testImplementation("org.seleniumhq.selenium:selenium-firefox-driver:3.141.59")
    testImplementation("com.squareup.okhttp3:okhttp:4.9.0")
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.1.4")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    testImplementation("org.hamcrest:hamcrest:2.2")
    testImplementation("org.testcontainers:testcontainers:1.19.1")
    testImplementation("org.testcontainers:junit-jupiter:1.19.1")
    testImplementation("org.testcontainers:nginx:1.19.1")
    testImplementation("org.testcontainers:selenium:1.19.1")
}

group = "de.njsm.tiny-auth"
version = "1.0"
description = "test"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

tasks.withType<Test> {
    inputs.file("$projectDir/../src/rust/target/debug/tiny-auth")

    useJUnitPlatform()
    systemProperty("de.njsm.tinyauth.test.root", "$projectDir/..")

    systemProperty("junit.jupiter.execution.parallel.enabled", "true")
    systemProperty("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")
    systemProperty("junit.jupiter.execution.parallel.config.strategy", "fixed")
    systemProperty("junit.jupiter.execution.parallel.config.fixed.parallelism", "2")
    systemProperty("junit.jupiter.execution.parallel.config.fixed.max-pool-size", "2")

    systemProperty("javax.net.ssl.keyStore", "$projectDir/src/test/resources/keys/client-store.jks")
    systemProperty("javax.net.ssl.keyStorePassword", "password")
    systemProperty("javax.net.ssl.keyStoreType", "JKS")
    systemProperty("javax.net.ssl.trustStore", "$projectDir/src/test/resources/keys/client-store.jks")
    systemProperty("javax.net.ssl.trustStorePassword", "password")
    systemProperty("javax.net.ssl.trustStoreType", "JKS")

    environment("TESTCONTAINERS_RYUK_DISABLED", "true")
}
