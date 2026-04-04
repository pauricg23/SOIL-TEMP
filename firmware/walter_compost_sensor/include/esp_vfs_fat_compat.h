// Compatibility wrapper for WalterModem library
// ESP32-S3 uses different FAT mount function names

#ifndef ESP_VFS_FAT_COMPAT_H
#define ESP_VFS_FAT_COMPAT_H

#include "esp_vfs_fat.h"

#ifdef __cplusplus
extern "C" {
#endif

// Compatibility: esp_vfs_fat_spiflash_mount_rw_wl -> esp_vfs_fat_spiflash_mount
// The library expects a function that doesn't exist, so we create a wrapper
esp_err_t esp_vfs_fat_spiflash_mount_rw_wl(
    const char* base_path,
    const char* partition_label,
    const esp_vfs_fat_mount_config_t* mount_config,
    wl_handle_t* wl_handle);

#ifdef __cplusplus
}
#endif

#endif // ESP_VFS_FAT_COMPAT_H

