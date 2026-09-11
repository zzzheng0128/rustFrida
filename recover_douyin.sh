#!/system/bin/sh
# recover_douyin.sh — 抖音启动必崩(libstagefright/scudo) 的一键恢复
#
# 背景：测试期 SIGKILL 打断视频缓存写入 → SD 卡缓存损坏 → 每次启动播首屏
# 视频时播放器堆破坏 → scudo malloc 跳 0x30 SIGSEGV。pm clear 无效
# （不擦 /sdcard/Android/data），且会丢登录态。本脚本只清 SD 缓存，保登录。
#
# 用法: su -c 'sh /data/local/tmp/recover_douyin.sh'

PKG=com.ss.android.ugc.aweme

echo "[*] force-stop $PKG"
am force-stop $PKG

echo "[*] backup+remove SD cache"
D=/sdcard/Android/data/$PKG
if [ -d "$D/cache" ]; then
    rm -rf "$D/cache.bak"
    mv "$D/cache" "$D/cache.bak"
    echo "    moved $D/cache -> $D/cache.bak (确认恢复后可删)"
fi

echo "[*] relaunch"
am start -n $PKG/.main.MainActivity >/dev/null 2>&1
sleep 12
if pidof $PKG >/dev/null 2>&1; then
    echo "[OK] $PKG alive (pid $(pidof $PKG))"
else
    echo "[FAIL] still not alive; check logcat/tombstones"
fi
