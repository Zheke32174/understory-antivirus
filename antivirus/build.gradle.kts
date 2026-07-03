plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.antivirus"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.antivirus"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-skeleton"
        resourceConfigurations += listOf("en")
        base.archivesName = "antivirus"
    }

    buildTypes {
        debug {
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // BuildConfig.FLAVOR gates the eng-only Diagnostics affordance out of
        // the shipping (prod) UI. AGP 8 disables BuildConfig generation by
        // default, so it is enabled explicitly here.
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    // Robolectric needs Android resources on the unit-test classpath so the
    // BlocklistCodec / seed tests can read res/raw/blocklist_seed.ubl.
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    flavorDimensions += "channel"
    productFlavors {
        create("prod") {
            dimension = "channel"
        }
        create("eng") {
            dimension = "channel"
            applicationIdSuffix = ".eng"
            versionNameSuffix = "-eng"
        }
    }
}

dependencies {
    implementation(project(":common-security"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    // ViewModel in Compose (scan/audit state survival across recreation, D#16).
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    // LocalLifecycleOwner + LifecycleEventObserver for the on-open PACKAGE_ADDED
    // watcher (§5.1 freshness-while-open).
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    // Material icons (ChevronRight, etc.) for the audit-row affordance.
    implementation("androidx.compose.material:material-icons-extended")

    // Periodic re-scan (§5) — WorkManager. This is the only viable rootless
    // "watch for new/updated apps" mechanism; inotify on /data/app is
    // impossible rootless and manifest PACKAGE_ADDED receivers are dead since
    // API 26 (see SUITE_ROADMAP.md).
    implementation("androidx.work:work-runtime-ktx:2.9.1")

    testImplementation("junit:junit:4.13.2")
    // Robolectric gives unit tests a working org.json + resource loader so the
    // BlocklistCodec / seed tests run on the JVM without an emulator (mirrors
    // common-security's test setup).
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
}
