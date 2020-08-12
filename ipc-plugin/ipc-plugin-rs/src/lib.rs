use suricata::{SCLogDebug, SCLogInfo, SCLogNotice};

use packet_ipc::{AsIpcPacket, Client, Packet as IpcPacket};
use std::sync::Arc;

pub struct IpcClient {
    pub inner: Client,
}

//IPC Integration
pub enum SCPacket {}
extern {
    fn ipc_set_packet_data(
        packet: *mut SCPacket,
        pktdata: *const u8,
        pktlen: u32,
        linktype: u32,
        tv_sec: u32,
        tv_usec: u32,
        user: *mut std::os::raw::c_void
    ) -> u32;
}

#[no_mangle]
pub extern "C" fn rs_ipc_release_packet(user: *mut u8) {
    SCLogInfo!("Releasing ipc packet");
    if user != std::ptr::null_mut() {
        unsafe {
            let packet = std::mem::transmute::<*mut u8, *mut IpcPacket>(user);
            let _packet = Arc::from_raw(packet);
            std::mem::drop(_packet);
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_ipc_populate_packets(ipc: *mut IpcClient, packets: *mut *mut SCPacket, len: u64) -> i64 {
    if ipc.is_null() {
        SCLogNotice!("IPC passed to ipc_populate_packets was null");
        return -1;
    }

    if packets.is_null() {
        SCLogNotice!("Packets passed to ipc_populate_packets was null");
        return -1;
    }

    if len == 0 {
        SCLogNotice!("No packets requested");
        return -1;
    }

    SCLogDebug!("Populating {} packets", len);

    match unsafe { (*ipc).inner.recv(len as usize) } {
        Err(_) => {
            SCLogNotice!("Failed to receive packets in ipc_populate_packets");
            return -1;
        }
        Ok(None) => {
            SCLogInfo!("IPC connection closed");
            return 0;
        }
        Ok(Some(mut ipc_packets)) => {
            if ipc_packets.is_empty() {
                SCLogInfo!("IPC connection closed");
                return 0;
            } else {
                SCLogDebug!("Received {} packets", ipc_packets.len());
                let packets_returned = ipc_packets.len();

                if packets_returned > len as usize {
                    SCLogNotice!("Incorrect number of packets returned ({}) vs available ({})", packets_returned, len);
                    return -1;
                }

                for (idx, packet) in ipc_packets.drain(..).enumerate() {
                    let raw_p = unsafe { *packets.offset(idx as isize) };
                    if raw_p.is_null() {
                        return -1;
                    }
                    if let Ok(dur) = packet.timestamp().duration_since(std::time::UNIX_EPOCH) {
                        let data_ptr = packet.data().as_ptr();
                        if data_ptr.is_null() {
                            SCLogNotice!("Packet data was null");
                            return -1;
                        }
                        let data_len = packet.data().len() as u32;
                        if unsafe { ipc_set_packet_data(
                            raw_p,
                            data_ptr,
                            data_len,
                            1, //should probably come with the packet
                            dur.as_secs() as _,
                            dur.subsec_micros() as _,
                            Arc::into_raw(packet) as *mut std::os::raw::c_void
                        ) } != 0  {
                            SCLogNotice!("Failed to set packet data");
                            return -1;
                        }
                    } else {
                        SCLogNotice!("Unable to convert timestamp to timeval in ipc_populate_packets");
                        return -1;
                    }
                }
                return packets_returned as _;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_create_ipc_client(server_name: *const std::os::raw::c_char, client: *mut *mut IpcClient) -> u32 {
    let server = unsafe { std::ffi::CStr::from_ptr(server_name) };
    if let Ok(s) = server.to_str() {
        if let Ok(ipc) = Client::new(s.to_string()) {
            let raw = Box::into_raw(Box::new(IpcClient { inner: ipc }));
            unsafe { *client = raw };
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn rs_release_ipc_client(ipc: *mut IpcClient) {
    let _ipc: Box<IpcClient> = unsafe { Box::from_raw(ipc) };
    std::mem::drop(_ipc);
}