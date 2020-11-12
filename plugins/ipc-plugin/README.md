# ipc-plugin

IPC Plugin is used to share packets with suricata, functioning as a packet source.

## Requirements

* CMake 3.0+ (Tested with 3.18+)
* make

## Building

The IPC Plugin requires suricata source, currently from the following branch:

    https://github.com/dbcfd/suricata/tree/4070-packet-reinit-api-2

To obtain the branch

    git clone https://github.com/dbcfd/suricata.git
    git checkout -b 4070-packet-reinit-api-2 origin/4070-packet-reinit-api-2
   
`suricata-ipc` requires this version of suricata to run. To build this version of suricata:
   
    autoreconf -i
    ./configure \
        --enable-pcre-jit \
        --disable-gccmarch-native \
        --with-unix-socket
    make install
    make install-conf

Building of the plugin expects suricata to live in `/build/suricata`. If you did not check out suricata to that location, then you must change the suricata dependency in `ipc-plugin-rs/Cargo.toml` to point at this suricata location.

To build, you will need to run cmake, then make.

    export SURICATA_SRC_DIR=/path/to/suricata
    cmake -S . -B build
    cd build
    make
    make install

The plugin will now be installed into your USER_PREFIX, likely `/usr/local/lib/libipc-plugin.so`.
