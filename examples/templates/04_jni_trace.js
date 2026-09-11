/*
 * JNI 系统调用追踪模板。
 *
 * 这里追踪的是当前线程 JNIEnv->functions 表，不是某一个 App 自定义的
 * native 方法。覆盖 93 个常用 JNI 1.6 槽位，包括类/方法/字段解析、
 * 对象引用、Java 调用、字符串/数组、异常、RegisterNatives、同步和
 * DirectByteBuffer 路径。
 *
 * spawn 模式必须把安装逻辑放进 Java.ready；否则 JVM/当前线程 JNIEnv
 * 还没有建立时，Jni.addr() 会失败，甚至会让早期注入卡住。
 */
(function () {
    "use strict";

    var TAG = "jni-system";
    var MAX_DETAIL = 5;
    var REPORT_EVERY = 200;

    // JNI 1.6 JNIEnv 表槽位。槽位由 jni.h 的四个 reserved 指针之后开始，
    // Jni.addr(name) 会按名字解析当前线程的函数地址。
    var SLOTS = [
        { slot: 4, name: "GetVersion", detail: "none" },
        { slot: 5, name: "DefineClass", detail: "cstr1" },
        { slot: 6, name: "FindClass", detail: "cstr1" },
        { slot: 7, name: "FromReflectedMethod", detail: "ref1" },
        { slot: 8, name: "FromReflectedField", detail: "ref1" },
        { slot: 10, name: "GetSuperclass", detail: "ref1" },
        { slot: 11, name: "IsAssignableFrom", detail: "ref2" },
        { slot: 13, name: "Throw", detail: "ref1" },
        { slot: 14, name: "ThrowNew", detail: "thrownew" },
        { slot: 15, name: "ExceptionOccurred", detail: "none" },
        { slot: 16, name: "ExceptionDescribe", detail: "none" },
        { slot: 17, name: "ExceptionClear", detail: "none" },
        { slot: 19, name: "PushLocalFrame", detail: "int1" },
        { slot: 20, name: "PopLocalFrame", detail: "ref1" },
        { slot: 21, name: "NewGlobalRef", detail: "ref1" },
        { slot: 22, name: "DeleteGlobalRef", detail: "ref1" },
        { slot: 23, name: "DeleteLocalRef", detail: "ref1" },
        { slot: 24, name: "IsSameObject", detail: "ref2" },
        { slot: 25, name: "NewLocalRef", detail: "ref1" },
        { slot: 26, name: "EnsureLocalCapacity", detail: "int1" },
        { slot: 27, name: "AllocObject", detail: "ref1" },
        { slot: 30, name: "NewObjectA", detail: "call" },
        { slot: 31, name: "GetObjectClass", detail: "ref1" },
        { slot: 32, name: "IsInstanceOf", detail: "ref2" },
        { slot: 33, name: "GetMethodID", detail: "cstr2" },
        { slot: 36, name: "CallObjectMethodA", detail: "call" },
        { slot: 39, name: "CallBooleanMethodA", detail: "call" },
        { slot: 51, name: "CallIntMethodA", detail: "call" },
        { slot: 54, name: "CallLongMethodA", detail: "call" },
        { slot: 63, name: "CallVoidMethodA", detail: "call" },
        { slot: 66, name: "CallNonvirtualObjectMethodA", detail: "call" },
        { slot: 81, name: "CallNonvirtualIntMethodA", detail: "call" },
        { slot: 93, name: "CallNonvirtualVoidMethodA", detail: "call" },
        { slot: 94, name: "GetFieldID", detail: "cstr2" },
        { slot: 95, name: "GetObjectField", detail: "ref1" },
        { slot: 100, name: "GetIntField", detail: "ref1" },
        { slot: 104, name: "SetObjectField", detail: "ref1" },
        { slot: 109, name: "SetIntField", detail: "ref1" },
        { slot: 113, name: "GetStaticMethodID", detail: "cstr2" },
        { slot: 116, name: "CallStaticObjectMethodA", detail: "call" },
        { slot: 119, name: "CallStaticBooleanMethodA", detail: "call" },
        { slot: 131, name: "CallStaticIntMethodA", detail: "call" },
        { slot: 134, name: "CallStaticLongMethodA", detail: "call" },
        { slot: 143, name: "CallStaticVoidMethodA", detail: "call" },
        { slot: 144, name: "GetStaticFieldID", detail: "cstr2" },
        { slot: 145, name: "GetStaticObjectField", detail: "ref1" },
        { slot: 150, name: "GetStaticIntField", detail: "ref1" },
        { slot: 154, name: "SetStaticObjectField", detail: "ref1" },
        { slot: 159, name: "SetStaticIntField", detail: "ref1" },
        { slot: 163, name: "NewString", detail: "none" },
        { slot: 164, name: "GetStringLength", detail: "ref1" },
        { slot: 165, name: "GetStringChars", detail: "ref1" },
        { slot: 166, name: "ReleaseStringChars", detail: "ref1" },
        { slot: 167, name: "NewStringUTF", detail: "cstr1" },
        { slot: 168, name: "GetStringUTFLength", detail: "ref1" },
        { slot: 169, name: "GetStringUTFChars", detail: "ref1" },
        { slot: 170, name: "ReleaseStringUTFChars", detail: "ref1" },
        { slot: 171, name: "GetArrayLength", detail: "ref1" },
        { slot: 172, name: "NewObjectArray", detail: "array" },
        { slot: 173, name: "GetObjectArrayElement", detail: "ref1" },
        { slot: 174, name: "SetObjectArrayElement", detail: "ref1" },
        { slot: 175, name: "NewBooleanArray", detail: "int1" },
        { slot: 177, name: "NewByteArray", detail: "int1" },
        { slot: 179, name: "NewIntArray", detail: "int1" },
        { slot: 183, name: "GetBooleanArrayElements", detail: "ref1" },
        { slot: 184, name: "GetByteArrayElements", detail: "ref1" },
        { slot: 187, name: "GetIntArrayElements", detail: "ref1" },
        { slot: 191, name: "ReleaseBooleanArrayElements", detail: "ref1" },
        { slot: 192, name: "ReleaseByteArrayElements", detail: "ref1" },
        { slot: 195, name: "ReleaseIntArrayElements", detail: "ref1" },
        { slot: 199, name: "GetBooleanArrayRegion", detail: "ref1" },
        { slot: 200, name: "GetByteArrayRegion", detail: "ref1" },
        { slot: 203, name: "GetIntArrayRegion", detail: "ref1" },
        { slot: 207, name: "SetBooleanArrayRegion", detail: "ref1" },
        { slot: 208, name: "SetByteArrayRegion", detail: "ref1" },
        { slot: 211, name: "SetIntArrayRegion", detail: "ref1" },
        { slot: 215, name: "RegisterNatives", detail: "register" },
        { slot: 216, name: "UnregisterNatives", detail: "ref1" },
        { slot: 217, name: "MonitorEnter", detail: "ref1" },
        { slot: 218, name: "MonitorExit", detail: "ref1" },
        { slot: 219, name: "GetJavaVM", detail: "none" },
        { slot: 220, name: "GetStringRegion", detail: "ref1" },
        { slot: 221, name: "GetStringUTFRegion", detail: "ref1" },
        { slot: 222, name: "GetPrimitiveArrayCritical", detail: "ref1" },
        { slot: 224, name: "GetStringCritical", detail: "ref1" },
        { slot: 225, name: "ReleaseStringCritical", detail: "ref1" },
        { slot: 226, name: "NewWeakGlobalRef", detail: "ref1" },
        { slot: 227, name: "DeleteWeakGlobalRef", detail: "ref1" },
        { slot: 228, name: "ExceptionCheck", detail: "none" },
        { slot: 229, name: "NewDirectByteBuffer", detail: "none" },
        { slot: 230, name: "GetDirectBufferAddress", detail: "ref1" },
        { slot: 231, name: "GetDirectBufferCapacity", detail: "ref1" },
        { slot: 232, name: "GetObjectRefType", detail: "ref1" }
    ];

    var counts = Object.create(null);
    var attached = Object.create(null);

    function log(message) { console.log("[" + TAG + "] " + message); }
    function asNumber(value) {
        try {
            if (value && typeof value.toInt32 === "function") return value.toInt32();
        } catch (_) {}
        var n = Number(value);
        return isFinite(n) ? n : 0;
    }
    function asString(value) {
        try { return String(value || "0x0"); } catch (_) { return "<unprintable>"; }
    }
    function readCString(value) {
        try { return ptr(value).readCString(); } catch (_) { return "<unreadable>"; }
    }
    function detail(slot, args) {
        try {
            if (slot.detail === "cstr1") return " text='" + readCString(args[1]) + "'";
            if (slot.detail === "cstr2") return " name='" + readCString(args[2]) +
                "' sig='" + readCString(args[3]) + "'";
            if (slot.detail === "thrownew") return " msg='" + readCString(args[2]) + "'";
            if (slot.detail === "int1") return " value=" + asNumber(args[1]);
            if (slot.detail === "ref1") return " ref=" + asString(args[1]);
            if (slot.detail === "ref2") return " ref1=" + asString(args[1]) +
                " ref2=" + asString(args[2]);
            if (slot.detail === "call") return " obj=" + asString(args[1]) +
                " method=" + asString(args[2]);
            if (slot.detail === "array") return " len=" + asNumber(args[1]) +
                " clazz=" + asString(args[2]);
            if (slot.detail === "register") {
                var firstName = "<none>";
                try { firstName = readCString(args[2].readPointer()); } catch (_) {}
                return " count=" + asNumber(args[3]) + " first='" + firstName + "'";
            }
        } catch (_) {}
        return "";
    }
    function validAddress(value) {
        if (value === null || value === undefined) return false;
        try { return String(ptr(value)) !== "0x0"; } catch (_) { return false; }
    }

    function installSlot(slot) {
        var address = null;
        try { address = Jni.addr(slot.name); } catch (error) {
            log("Jni.addr " + slot.name + " failed: " + (error.message || error));
            return false;
        }
        if (!validAddress(address)) {
            log(slot.name + " unavailable");
            return false;
        }
        var addressKey = String(ptr(address));
        if (attached[addressKey]) {
            attached[addressKey].push(slot.name);
            return true;
        }
        counts[slot.name] = 0;
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    counts[slot.name]++;
                    var n = counts[slot.name];
                    if (n <= MAX_DETAIL || n % REPORT_EVERY === 0) {
                        log(slot.name + " #" + n + " slot=" + slot.slot + detail(slot, args));
                    }
                }
            });
            attached[addressKey] = [slot.name];
            log("hooked " + slot.name + " slot=" + slot.slot + " at " + address);
            return true;
        } catch (error) {
            log("attach " + slot.name + " failed: " + (error.message || error));
            return false;
        }
    }

    function install() {
        var installed = 0;
        for (var i = 0; i < SLOTS.length; i++) {
            if (installSlot(SLOTS[i])) installed++;
        }
        log("table hooks installed=" + installed + "/" + SLOTS.length +
            " distinct-addresses=" + Object.keys(attached).length);
    }

    if (typeof Java !== "undefined" && Java && Java.ready) {
        Java.ready(function () {
            log("java ready, installing JNIEnv table hooks");
            install();
        });
    } else {
        log("Java API unavailable");
    }
})();
