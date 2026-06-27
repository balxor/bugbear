/*
  YARA Rules for Uptodown App Store v7.32 Detection
  Prepared: 2026-06-28 00:52:36
  Purpose: Detect Uptodown APK and related artifacts
*/

rule Uptodown_APK_v732 {
    meta:
        description = "Detects Uptodown App Store v7.32 APK"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
        category = "telemetry"
    
    hash:
        sha256 = "863f05e8c42a2fbf870388bba81383c05469a387f1e6e92707198fe89cd38c5e"
    
    strings:
        $pkg = "com.uptodown" ascii
        $ver = "7.32" ascii
        $main_activity = "com.uptodown.activities.MainActivity" ascii
        $app_class = "com.uptodown.UptodownApp" ascii
        $tracker_ep = "/eapi/v2/tracker/device" ascii
        $inventory_ep = "/eapi/androidtracker/device-apps-installed" ascii
    
    condition:
        $pkg and $ver and ($main_activity or $app_class)
        and ($tracker_ep or $inventory_ep)
}

rule Uptodown_Native_Library {
    meta:
        description = "Detects Uptodown native library"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $jni1 = "Java_com_uptodown_util_NativeApiKey_getAuthApikey" ascii
        $jni2 = "Java_com_uptodown_util_NativeApiKey_getAuthApikeyLite" ascii
        $lib_name = "libuptodown-native.so" ascii
    
    condition:
        ($jni1 and $jni2) or $lib_name
}

rule Uptodown_Tracker_Database {
    meta:
        description = "Detects Uptodown tracker SQLite database"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $sqlite = "SQLite format 3" ascii
        $table1 = "CREATE TABLE device_status" ascii
        $table2 = "CREATE TABLE data_usage" ascii
        $table3 = "CREATE TABLE apps" ascii
        $col1 = "batteryLevel" ascii
        $col2 = "uploadSpeedKbps" ascii
        $col3 = "packagename" ascii
    
    condition:
        $sqlite and ($table1 or $table2 or $table3)
        and ($col1 or $col2 or $col3)
}

rule Uptodown_Tracking_Strings {
    meta:
        description = "Detects Uptodown tracking-related strings"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $tracker_url = "t.uptodown.app" ascii
        $api_url = "www.uptodown.app:443" ascii
        $upload_url = "u.uptodown.app" ascii
        $ep1 = "/eapi/v2/tracker/" ascii
        $ep2 = "/eapi/v3/device/" ascii
        $ep3 = "/eapi/user-data/" ascii
        $ep4 = "/eapi/androidtracker/" ascii
    
    condition:
        ($tracker_url or $api_url or $upload_url)
        and ($ep1 or $ep2 or $ep3 or $ep4)
}

rule Firebase_Analytics_Database {
    meta:
        description = "Detects Firebase Analytics database with Uptodown data"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $sqlite = "SQLite format 3" ascii
        $table1 = "CREATE TABLE events" ascii
        $table2 = "CREATE TABLE raw_events" ascii
        $table3 = "CREATE TABLE user_attributes" ascii
        $table4 = "CREATE TABLE upload_queue" ascii
    
    condition:
        $sqlite and ($table1 or $table2)
        and ($table3 or $table4)
}

rule Uptodown_Boot_Persistence {
    meta:
        description = "Detects Uptodown boot persistence mechanism"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $receiver = "BootDeviceReceiver" ascii
        $action = "android.intent.action.BOOT_COMPLETED" ascii
        $package = "com.uptodown.receivers" ascii
    
    condition:
        $receiver and $action and $package
}

rule Uptodown_Anti_Analysis {
    meta:
        description = "Detects Uptodown anti-analysis techniques"
        author = "Kenshin Himura - DTrust"
        date = "2026-06-28"
        severity = "medium"
    
    strings:
        $anti_debug = "isDebuggerConnected" ascii
        $anti_vm1 = "Build.FINGERPRINT" ascii
        $anti_vm2 = "Build.MANUFACTURER" ascii
        $anti_vm3 = "Build.HARDWARE" ascii
        $root_check = "/system/xbin/su" ascii
        $root_check2 = "Superuser.apk" ascii
    
    condition:
        ($anti_debug) or ($anti_vm1 and $anti_vm2 and $anti_vm3)
        or ($root_check or $root_check2)
}
