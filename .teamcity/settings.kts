import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildFeatures.commitStatusPublisher
import jetbrains.buildServer.configs.kotlin.buildSteps.gradle
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.triggers.ScheduleTrigger
import jetbrains.buildServer.configs.kotlin.triggers.schedule
import jetbrains.buildServer.configs.kotlin.triggers.vcs

/*
The settings script is an entry point for defining a TeamCity
project hierarchy. The script should contain a single call to the
project() function with a Project instance or an init function as
an argument.

VcsRoots, BuildTypes, Templates, and subprojects can be
registered inside the project using the vcsRoot(), buildType(),
template(), and subProject() methods respectively.

To debug settings scripts in command-line, run the

    mvnDebug org.jetbrains.teamcity:teamcity-configs-maven-plugin:generate

command and attach your debugger to the port 8000.

To debug in IntelliJ Idea, open the 'Maven Projects' tool window (View
-> Tool Windows -> Maven Projects), find the generate task node
(Plugins -> teamcity-configs -> teamcity-configs:generate), the
'Debug' option is available in the context menu for the task.
*/

version = "2024.03"

project {

    buildType(Build)
}

object Build : BuildType({
    templates(AbsoluteId("Projects_Alerter_RustProject"))
    name = "Build"

    artifactRules = "test/build/reports/"

    params {
        param("RUST_ROOT", "src/rust")
        param("env.XDG_RUNTIME_DIR", "/run/user/%env.UID%/")
    }

    vcs {
        root(DslContext.settingsRoot)
    }

    steps {
        script {
            name = "npm build"
            id = "npm_check"
            workingDir = "src/typescript"
            scriptContent = """
                set -e
                npm install
                mkdir -p src/generated
                npx protoc \
                            --ts_out src/generated \
                            --ts_opt long_type_string,generate_dependencies,optimize_code_size \
                            --proto_path ../proto \
                            ../proto/tiny-auth/tiny-auth.proto
                npm run build
                npx prettier . --check
                npm run lint
                npm audit
            """.trimIndent()
        }
        gradle {
            name = "System Test"
            id = "RUNNER_27"
            tasks = "check"
            buildFile = "build.gradle.kts"
            workingDir = "test"
        }
        script {
            name = "Cargo Build"
            id = "RUNNER_14"
            workingDir = "src/rust"
            scriptContent = "cargo build"
        }
        script {
            name = "Cargo Fmt"
            id = "RUNNER_17"
            workingDir = "src/rust"
            scriptContent = "cargo fmt --all -- --check"
        }
        script {
            name = "Cargo Clippy"
            id = "RUNNER_21"
            workingDir = "src/rust"
            scriptContent = "cargo clippy --release -j 8 -- -D clippy::all"
        }
        script {
            name = "Cargo Test"
            id = "RUNNER_22"
            workingDir = "src/rust"
            scriptContent = "cargo test -j 1"
        }
        script {
            name = "Cargo Check"
            id = "cargo_check"
            workingDir = "%RUST_ROOT%"
            scriptContent = "cargo check"
        }
    }

    triggers {
        vcs {
            id = "TRIGGER_8"
        }
        schedule {
            id = "TRIGGER_9"
            schedulingPolicy = weekly {
                dayOfWeek = ScheduleTrigger.DAY.Tuesday
                hour = 19
            }
            branchFilter = "+:master"
            triggerBuild = always()
            withPendingChangesOnly = false
        }
    }

    features {
        commitStatusPublisher {
            id = "BUILD_EXT_1"
            vcsRootExtId = "${DslContext.settingsRoot.id}"
            publisher = github {
                githubUrl = "https://veenj.de/git/api/v1"
                authType = personalToken {
                    token = "credentialsJSON:557337ec-b35f-4879-a148-11d578a847a4"
                }
            }
        }
    }
})
