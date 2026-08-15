#!/system/bin/sh
# ============================================================================
# example_script.sh - 示例：需要加密保护的优化脚本
#
# 这个脚本模拟一个 Android 系统优化脚本，包含敏感操作逻辑。
# 加密后，别人无法看到原文，但 decrypt_bin 可以解密并执行。
# ============================================================================

echo "=========================================="
echo "  Android System Optimizer (Encrypted)"
echo "=========================================="

# --- 清理缓存 ---
echo "[*] Cleaning system caches..."
rm -rf /data/local/tmp/cache_*
rm -rf /cache/*
rm -rf /data/dalvik-cache/*

# --- 内存优化 ---
echo "[*] Optimizing memory..."
sync
echo 3 > /proc/sys/vm/drop_caches

# --- 后台进程清理 ---
echo "[*] Trimming background processes..."
am kill-all

# --- 数据库优化 ---
echo "[*] Optimizing databases..."
sqlite3 /data/data/com.android.providers.settings/databases/settings.db "VACUUM;"
sqlite3 /data/data/com.android.providers.contacts/databases/contacts.db "VACUUM;"

# --- 网络优化 ---
echo "[*] Flushing network..."
ndc network flush default

# --- 完成 ---
echo ""
echo "=========================================="
echo "  ✓ Optimization complete!"
echo "=========================================="
