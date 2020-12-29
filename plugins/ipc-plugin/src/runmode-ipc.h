/** \file
 *
 *  \author dbcfd <bdbrowning2@gmail.com>
 */
#ifndef __RUNMODE_IPC_H__
#define __RUNMODE_IPC_H__

typedef struct IpcConfig_
{
    char **servers;
    /* number of servers, one acquisition per server */
    int nb_servers;
    /* Packet allocation batch size, defaults to 100 */
    intmax_t allocation_batch;
    /* How large should the channel between ipc channel and suricata packet pool be. This channel contains batches of packets, NOT individual packets or bytes. 0 is unbounded. */
    intmax_t ipc_to_suricata_channel_size;

    /* ref counter for shared config */
    SC_ATOMIC_DECLARE(unsigned int, ref);
    /* ref counter for server index */
    SC_ATOMIC_DECLARE(unsigned int, server_id);
    void (*DerefFunc)(void *);
} IpcConfig;

int RunModeIpcSingle(void);
int RunModeIpcAutoFp(void);
int RunModeIpcWorkers(void);
void RunModeIpcRegister(int plugin_slot);
__attribute__((visibility("default"))) const char *RunModeIpcGetDefaultMode(void);

#endif /* __RUNMODE_IPC_H__ */
