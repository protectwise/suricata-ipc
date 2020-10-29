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

__attribute__((visibility("default"))) int32_t ipc_set_packet_data(Packet *p, uint8_t *pktdata, uint32_t pktlen,
                            uint32_t linktype, uint32_t ts_sec, uint32_t ts_usec,
                            uint8_t *userdata);

#endif /* __SOURCE_IPC_H__ */

