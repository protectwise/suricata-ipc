#include <stdio.h>
#include <stdlib.h>

#include "bindings.h"
#include "suricata-common.h"
#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"

#define OUTPUT_NAME "kafka"

static int LogWrite(const char *buffer, int buffer_len, void *data)
{
    Client *client = data;
    if (client == NULL)
    {
        FatalError(SC_ERR_PLUGIN, "Null client for filetype plugin: %s", OUTPUT_NAME);
        return -1;
    }
    return send_to_logging_client(buffer, buffer_len, client);
}

static void LogClose(void *data)
{
    Client *client = data;
    if (client != NULL)
    {
        release_logging_client(client);
    }
}

static int LogOpen(ConfNode *conf, void **data)
{
    Client *client = create_logging_client(conf);
    if (client == NULL)
    {
        FatalError(SC_ERR_PLUGIN, "Failed to create filetype plugin: %s", OUTPUT_NAME);
        return -1;
    }
    *data = client;
    return 0;
}

void LogInit(void)
{
    SCPluginFileType *my_output = SCCalloc(1, sizeof(SCPluginFileType));
    my_output->name = OUTPUT_NAME;
    my_output->Open = LogOpen;
    my_output->Write = LogWrite;
    my_output->Close = LogClose;
    if (!SCPluginRegisterFileType(my_output))
    {
        FatalError(SC_ERR_PLUGIN, "Failed to register filetype plugin: %s", OUTPUT_NAME);
    }
}

const SCPlugin PluginRegistration = {
    .name = OUTPUT_NAME,
    .author = "dbcfd <bdbrowning2@gmail.com>",
    .license = "MIT",
    .Init = LogInit,
};

__attribute__((visibility("default"))) const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}