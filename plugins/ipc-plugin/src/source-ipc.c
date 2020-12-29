#include "suricata-common.h"
#include "suricata.h"
#include "flow.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-ipc.h"
#include "conf.h"
#include "pkt-var.h"
#include "runmode-ipc.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-device.h"
#include "util-optimize.h"
#include "util-profiling.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "tmqh-packetpool.h"

static TmEcode ReceiveIpcLoop(ThreadVars *, void *, void *);
static TmEcode ReceiveIpcThreadInit(ThreadVars *, const void *, void **);
static void ReceiveIpcThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveIpcThreadDeinit(ThreadVars *, void *);

static TmEcode DecodeIpc(ThreadVars *, Packet *, void *);
static TmEcode DecodeIpcThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeIpcThreadDeinit(ThreadVars *tv, void *data);

/**
 * Pcap File Functionality
 */
void TmModuleReceiveIpcPluginRegister(int slot)
{
    tmm_modules[slot].name = "ReceiveIpc";
    tmm_modules[slot].ThreadInit = ReceiveIpcThreadInit;
    tmm_modules[slot].Func = NULL;
    tmm_modules[slot].PktAcqLoop = ReceiveIpcLoop;
    tmm_modules[slot].PktAcqBreakLoop = NULL;
    tmm_modules[slot].ThreadExitPrintStats = ReceiveIpcThreadExitStats;
    tmm_modules[slot].ThreadDeinit = ReceiveIpcThreadDeinit;
    tmm_modules[slot].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[slot].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodeIpcPluginRegister (int slot)
{
    tmm_modules[slot].name = "DecodeIpc";
    tmm_modules[slot].ThreadInit = DecodeIpcThreadInit;
    tmm_modules[slot].Func = DecodeIpc;
    tmm_modules[slot].ThreadExitPrintStats = NULL;
    tmm_modules[slot].ThreadDeinit = DecodeIpcThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_DECODE_TM;
}

static void FreeAllocatedPackets(Packet **packets, int64_t packets_from_pool, int64_t packets_used) {
    SCLogDebug("%" PRIi64 "packets were unused", packets_from_pool - packets_used);
    for(int p = packets_used; p < packets_from_pool; ++p) {
        PacketFreeOrRelease(packets[p]);
    }
    SCFree(packets);
}

static void IpcPacketReinit(Packet *p) {
    if(p->reinit_data) {
        rs_ipc_release_packet(p->reinit_data);
    }
    p->reinit_data = NULL;
    PacketReinit(p);
}

int32_t ipc_set_packet_data(Packet *p, uint8_t *pktdata, uint32_t pktlen,
                             uint32_t linktype, uint32_t ts_sec, uint32_t ts_usec,
                             uint8_t *userdata) {
    if(unlikely(PacketSetData(p, pktdata, pktlen) != 0)) {
        return -1;
    }
    p->datalink = linktype;
    p->ts.tv_sec = ts_sec;
    p->ts.tv_usec = ts_usec;
    p->reinit_data = userdata;
    p->ReinitPacket = IpcPacketReinit;

    return 0;
}

TmEcode ReceiveIpcLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    IpcThreadVars *ptv = (IpcThreadVars *) data;

    if(unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No IPC Vars");
        SCReturnInt(TM_ECODE_FAILED);
    }

    TmSlot *s = (TmSlot *)slot;
    Packet **current_packets = NULL;
    Packet *packet = NULL;
    int64_t packets_used = ptv->allocation_batch;

    ptv->slot = s->slot_next;

    while (!(suricata_ctl_flags & SURICATA_STOP || suricata_ctl_flags & SURICATA_DONE)) {
        if(ptv->allocation_batch == packets_used) {
            if(current_packets) {
                FreeAllocatedPackets(current_packets, ptv->allocation_batch, packets_used);
            }
            current_packets = NULL;
            packets_used = 0;

            SCLogDebug("Waiting for %"PRIi64" packets from suricata", ptv->allocation_batch);

            /* make sure we have at least one packet in the packet pool, to prevent
             * us from alloc'ing packets at line rate */
            PacketPoolWaitForN(ptv->allocation_batch);

            current_packets = SCMalloc(
                    sizeof(Packet *) * ptv->allocation_batch);

            if (unlikely(current_packets == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC,
                           "Failure allocating packets array");
                SCReturnInt(TM_ECODE_FAILED);
            }
            memset(current_packets, 0,
                   sizeof(Packet *) * ptv->allocation_batch);

            for (int p = 0; p < ptv->allocation_batch; ++p) {
                packet = PacketPoolGetPacket();

                if (unlikely(packet == NULL)) {
                    FreeAllocatedPackets(current_packets, p, 0);
                    SCLogError(SC_ERR_MEM_ALLOC, "Failure getting packet");
                    SCReturnInt(TM_ECODE_FAILED);
                }

                current_packets[p] = packet;
            }
        }

        SCLogDebug("Allocation batch - packets_used %"PRIi64" - %"PRIi64"", ptv->allocation_batch, packets_used);

        int64_t packets_available = ptv->allocation_batch - packets_used;
        int64_t packets_received = rs_ipc_populate_packets(ptv->ipc, (SCPacket **)&current_packets[packets_used], packets_available);

        SCLogDebug("Received %" PRIi64 " packets from ipc", packets_received);
        if(unlikely(packets_received < 0)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failure getting packets from ipc");
            FreeAllocatedPackets(current_packets, ptv->allocation_batch, packets_used);
            SCReturnInt(TM_ECODE_FAILED);
        } else if(packets_received == 0) {
            SCLogInfo("IPC connection closed, releasing packets");
            FreeAllocatedPackets(current_packets, ptv->allocation_batch, packets_used);
            EngineStop();
            StatsSyncCountersIfSignalled(tv);
            SCLogInfo("IPC packet acquire loop, complete");
            SCReturnInt(TM_ECODE_DONE);
        } else {
            //process all packets
            ptv->pkts += packets_received;
            for(int p = 0; p < packets_received; ++p) {
                packet = current_packets[packets_used + p];
                ptv->bytes += GET_PKT_LEN(packet);
                PKT_SET_SRC(packet, PKT_SRC_WIRE);
                if (TmThreadsSlotProcessPkt(tv, ptv->slot, packet) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_PCAP_DISPATCH, "Failed to process packet");
                    TmqhOutputPacketpool(tv, packet);
                    FreeAllocatedPackets(current_packets, ptv->allocation_batch, packets_used + p);
                    SCReturnInt(TM_ECODE_FAILED);
                }
            };

            packets_used += packets_received;

            StatsSyncCountersIfSignalled(tv);
        }
    }

    if(current_packets) {
        FreeAllocatedPackets(current_packets, ptv->allocation_batch, packets_used);
    }
    SCReturnInt(TM_ECODE_DONE);
}

TmEcode ReceiveIpcThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    IpcConfig *ipc = (IpcConfig *) initdata;
    IpcClient *ipc_client = NULL;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");

        SCReturnInt(TM_ECODE_FAILED);
    }

    IpcThreadVars *ptv = SCMalloc(sizeof(IpcThreadVars));
    if (unlikely(ptv == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(IpcThreadVars));

    int server_id = SC_ATOMIC_ADD(ipc->server_id, 1);

    SCLogDebug("Initializing connection for ipc connection %d", server_id);

    ptv->server_name = SCStrdup(ipc->servers[server_id]);
    if(unlikely(ptv->server_name == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "Thread init failed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogInfo("Creating client to %s", ptv->server_name);

    if(!rs_create_ipc_client(ptv->server_name, &ipc_client, ipc->ipc_to_suricata_channel_size)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to connect to client at %s", ptv->server_name);
        SCFree(ptv->server_name);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    };

    ptv->ipc = ipc_client;
    ptv->allocation_batch = ipc->allocation_batch;
    
    *data = (void *)ptv;

    ipc->DerefFunc(initdata);

    SCLogInfo("IPC Source Ready, connected to %s, with batch size of %" PRIi64, ptv->server_name, ptv->allocation_batch);
    SCReturnInt(TM_ECODE_OK);
}

void ReceiveIpcThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    IpcThreadVars *ptv = (IpcThreadVars *)data;

    SCLogNotice(
            "Ipc module read %" PRIu64 " packets, %" PRIu64 " bytes",
            ptv->pkts,
            ptv->bytes
    );
}

TmEcode ReceiveIpcThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    IpcThreadVars *ptv = (IpcThreadVars *)data;
    if(ptv->ipc) {
        rs_release_ipc_client(ptv->ipc);
    }
    if(ptv->server_name) {
        SCFree(ptv->server_name);
    }
    SCFree(ptv);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodePcap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeIpc(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        case LINKTYPE_RAW:
        case LINKTYPE_GRE_OVER_IP:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodePcap", p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeIpcThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeIpcThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

