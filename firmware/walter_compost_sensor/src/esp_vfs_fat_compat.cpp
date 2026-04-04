// Implementation of compatibility wrapper for WalterModem library

#include "esp_vfs_fat_compat.h"

extern "C" {
esp_err_t esp_vfs_fat_spiflash_mount_rw_wl(
    const char* base_path,
    const char* partition_label,
    const esp_vfs_fat_mount_config_t* mount_config,
    wl_handle_t* wl_handle) {
    // Use the standard mount function - it's already read-write with wear levelling
    return esp_vfs_fat_spiflash_mount(base_path, partition_label, mount_config, wl_handle);
}
}

