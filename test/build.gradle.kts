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
    testImplementation("com.google.code.gson:gson:2.8.6")
    testImplementation("org.apache.logging.log4j:log4j-api:2.13.3")
    testImplementation("org.apache.logging.log4j:log4j-core:2.13.3")
    testImplementation("org.apache.logging.log4j:log4j-web:2.13.3")
    testImplementation("org.apache.logging.log4j:log4j-slf4j-impl:2.13.3")
    testImplementation("commons-io:commons-io:2.7")
    testImplementation("io.burt:jmespath-core:0.5.0")
    testImplementation("io.burt:jmespath-gson:0.5.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.7.0")
    testImplementation("io.rest-assured:rest-assured:4.3.1")
    testImplementation("org.mock-server:mockserver-junit-jupiter:5.11.2")
    testImplementation("org.seleniumhq.selenium:selenium-java:3.141.59")
    testImplementation("org.seleniumhq.selenium:selenium-firefox-driver:3.141.59")
    testImplementation("com.squareup.okhttp3:okhttp:4.9.0")
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.1.4")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.66")
    testImplementation("org.hamcrest:hamcrest:2.2")
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
    useJUnitPlatform()
    systemProperty("de.njsm.tinyauth.test.config.binary", "$projectDir/../src/rust/target/debug/tiny-auth")
    systemProperty("de.njsm.tinyauth.test.config.configfile", "$projectDir/src/test/resources/config.yml")
    systemProperty("de.njsm.tinyauth.test.config.logconfigfile", "$projectDir/src/test/resources/log4rs.yml")
    systemProperty("de.njsm.tinyauth.test.selenium.profile", "$projectDir/src/test/resources/firefox/")

    systemProperty("javax.net.ssl.keyStore", "$projectDir/src/test/resources/keys/client-store.jks")
    systemProperty("javax.net.ssl.keyStorePassword", "password")
    systemProperty("javax.net.ssl.keyStoreType", "JKS")
    systemProperty("javax.net.ssl.trustStore", "$projectDir/src/test/resources/keys/client-store.jks")
    systemProperty("javax.net.ssl.trustStorePassword", "password")
    systemProperty("javax.net.ssl.trustStoreType", "JKS")
}
