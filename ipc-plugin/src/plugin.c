#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>
#include "suricata-common.h"
#include "suricata-plugin.h"

#include "decode.h"
#include "runmode-ipc.h"
#include "source-ipc.h"
#include "util-device.h"

static char *source_name = "ipc-plugin";

void InitCapturePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    LiveBuildDeviceList("ipc");
    RunModeIpcRegister(plugin_slot);
    TmModuleReceiveIpcPluginRegister(receive_slot);
    TmModuleDecodeIpcPluginRegister(decode_slot);
}

void SCPluginInit(void)
{
    SCLogNotice("SCPluginInit");
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for capture plugin");
    }
    plugin->name = source_name;
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = RunModeIpcGetDefaultMode;
    SCPluginRegisterCapture(plugin);
}

const SCPlugin PluginSpec = {
        .name = "ipc-plugin",
        .author = "dbcfd <bdbrowning2@gmail.com>",
        .license = "MIT",
        .Init = SCPluginInit,
};

__attribute__((visibility("default"))) const SCPlugin *SCPluginRegister()
{
    return &PluginSpec;
}