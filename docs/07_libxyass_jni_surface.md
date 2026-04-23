# libxyass.so — JNI Surface Area (Unicorn emulation of `JNI_OnLoad`)

## Classes looked up via `FindClass` (25)

- `android/app/ActivityThread`
- `com/xingin/shield/http/Native`
- `android/content/Context`
- `java/lang/String`
- `android/content/SharedPreferences`
- `android/content/SharedPreferences$Editor`
- `android/content/pm/PackageManager`
- `okhttp3/Request`
- `okhttp3/HttpUrl`
- `okhttp3/Request$Builder`
- `okhttp3/RequestBody`
- `okhttp3/Headers`
- `okio/Buffer`
- `okhttp3/Interceptor$Chain`
- `java/util/List`
- `java/nio/charset/Charset`
- `com/xingin/shield/http/ContextHolder`
- `okhttp3/Response`
- `okhttp3/ResponseBody`
- `com/xingin/shield/http/Base64Helper`
- `android/app/Application`
- `android/content/pm/PackageManager`
- `android/app/Application`
- `android/content/pm/PackageInfo`
- `android/content/pm/Signature`

## Methods looked up via `GetMethodID`/`GetStaticMethodID` (6)

| Class | Method | Signature |
|---|---|---|
| `android/app/ActivityThread` | `currentApplication` | `()Landroid/app/Application;` |
| `com/xingin/shield/http/ContextHolder` | `writeLog` | `(I)V` |
| `android/app/Application` | `getPackageManager` | `()Landroid/content/pm/PackageManager;` |
| `android/content/pm/PackageManager` | `getPackageInfo` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;` |
| `android/app/Application` | `getPackageName` | `()Ljava/lang/String;` |
| `android/content/pm/Signature` | `hashCode` | `()I` |

## Fields looked up via `GetFieldID`/`GetStaticFieldID` (1)

| Class | Field | Type |
|---|---|---|
| `android/content/pm/PackageInfo` | `signatures` | `[Landroid/content/pm/Signature;` |

## Strings created via `NewStringUTF` (0)

