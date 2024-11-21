/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

plugins {
    id("org.liquibase.gradle")
}

group = "tiny-auth"
version = ""

dependencies {
    liquibaseRuntime(libs.liquibase) {
        exclude(group = "ch.qos.logback", module = "logback-classic")
    }
    liquibaseRuntime(libs.picocli)
    liquibaseRuntime(libs.jaxb.api)
    liquibaseRuntime(libs.slf4j)
    liquibaseRuntime(libs.sqlite)
}

val createBuildDir = tasks.register("createBuildDir") {
    doFirst {
        layout.buildDirectory.get().asFile.mkdir()
    }
}

liquibase {
    activities {
        register("main") {
            arguments = mapOf(
                "searchPath" to "$projectDir",
                "changelogFile" to "src/main/resources/migrations/master.xml",
                "url" to "jdbc:sqlite:$projectDir/build/" + project.properties["dbName"] + ".sqlite",
                "driver" to "org.sqlite.JDBC",
                "databaseChangelogTableName" to "databasechangelog",
                "databaseChangelogLockTableName" to "databasechangeloglock",
                "labels" to project.properties["liquibaseLabels"] as String,
            )
        }
    }
}

tasks.filter { it.group == "Liquibase" }
    .forEach {
        it.dependsOn(createBuildDir)
}
