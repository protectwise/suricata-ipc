/**
 * \file
 *
 * \author dbcfd <bdbrowning2@gmail.com>
 */

#ifndef __SOURCE_IPC_H__
#define __SOURCE_IPC_H__

#include "suricata-common.h"
#include "flow.h"
#include "tm-threads.h"
#include "bindings.h"

void TmModuleReceiveIpcPluginRegister(int slot);
void TmModuleDecodeIpcPluginRegister(int slot);

/* per packet Ipc vars */
typedef struct IpcThreadVars_
{
    char *server_name;
    IpcClient *ipc;
    int64_t allocation_batch;
    uint64_t pkts;
    uint64_t bytes;
    TmSlot *slot;
} IpcThreadVars;

#endif /* __SOURCE_IPC_H__ */

