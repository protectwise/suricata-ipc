# bellini

Library to enable packet sharing with suricata, and reading alerts from an eve
socket. Alerts read can then use an intel cache to determine additional metadata
about them.

## Develop With Docker
Install [lefthook](https://github.com/Arkweid/lefthook/blob/master/docs/full_guide.md). You can then run

    lefthook run develop

## Cloning
This repository uses submodules, so should be cloned with

    git clone --recurse-submodules -j8 git@github.com:OISF/suricata-verify.git
      
If you've already cloned, you'll need to update the submodules

    git submodule update --init --recursive
 