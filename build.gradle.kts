plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

group = "co.screenmate.can"
version = "0.1.0"

android {
    namespace = "co.screenmate.can.ipc"
    compileSdk = 34
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
