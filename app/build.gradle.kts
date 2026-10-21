import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing comes only from the environment (GitHub Secrets in CI). Nothing secret is stored in the repository.
val keystorePath: String? = System.getenv("KRATOS_KEYSTORE_PATH")
val haveReleaseKey: Boolean = !keystorePath.isNullOrBlank() && File(keystorePath).isFile &&
    !System.getenv("KRATOS_KEYSTORE_PASSWORD").isNullOrEmpty() &&
    !System.getenv("KRATOS_KEY_ALIAS").isNullOrEmpty() &&
    !System.getenv("KRATOS_KEY_PASSWORD").isNullOrEmpty()

android {
    namespace = "com.kratos.dump"
    compileSdk = 34
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.kratos.dump"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        externalNativeBuild {
            cmake {
                // The native build is limited to the two ARM ABIs; the universal APK then contains exactly these two.
                abiFilters += listOf("arm64-v8a", "armeabi-v7a")
                arguments += listOf(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON",
                    "-DCMAKE_BUILD_TYPE=Release"
                )
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("../core/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }

    signingConfigs {
        if (haveReleaseKey) {
            create("release") {
                storeFile = File(keystorePath!!)
                storePassword = System.getenv("KRATOS_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KRATOS_KEY_ALIAS")
                keyPassword = System.getenv("KRATOS_KEY_PASSWORD")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            // Without secrets the release build is signed with the debug key; CI labels such artifacts accordingly.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    lint {
        abortOnError = false
    }
}
