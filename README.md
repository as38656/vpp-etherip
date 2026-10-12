# EtherIP (RFC 3378) plugin for FD.io VPP

This repository contains a [VPP](https://fd.io/) plugin that implements
point-to-point EtherIP tunnels ([RFC 3378](https://www.rfc-editor.org/rfc/rfc3378)).
An EtherIP tunnel carries Ethernet frames over IPv4 or IPv6 (IP protocol 97)
with a 2 byte EtherIP header (version 3, reserved bits 0). A tunnel is a VPP
interface (`etherip<instance>`) that can join a bridge domain or an L2
cross-connect.

The plugin is **experimental** (`state: experimental` in
[`etherip/FEATURE.yaml`](etherip/FEATURE.yaml), API version 0.1.0). The binary
API, the CLI and the error counter names may change.

## Behavior

The receive and transmit behavior follows OpenBSD
[etherip(4)](https://man.openbsd.org/etherip.4) where VPP allows it:

- Received EtherIP packets are dropped until they are allowed with
  `set etherip allow on` (API `etherip_set_allow`). This corresponds to the
  OpenBSD sysctl `net.inet.etherip.allow`, which is 0 by default. As in
  OpenBSD `etherip_input()`, this check is made before all other receive
  checks. The OpenBSD exception for IPsec protected packets is not
  implemented. Transmission is not affected by this setting.
- A received packet whose EtherIP header is not version 3 with the reserved
  bits set to 0 (`0x30 0x00` on the wire) is dropped.
- The outer TTL / hop limit (default 64), the outer DSCP (default 0) and DF
  are configured per tunnel, like `tunnelttl` and `tunneldf` of
  ifconfig(8). With DF set, IPv4 packets have the DF bit set and IPv6
  packets are not fragmented by VPP at the source. The outer ECN bits are
  always 0 and the IPv6 flow label is 0.
- Outer IPv4 packets without DF get a 16 bit Identification from a per
  thread counter (OpenBSD uses `ip_randomid()` for every packet).

Other properties:

- A tunnel is identified by (outer FIB table, source address, destination
  address). A second tunnel with the same key is refused. The endpoints of a
  tunnel cannot be changed; delete and create the tunnel again.
- Received packets are checked in this order, each with its own error
  counter: allow policy, length (outer header + 2 + 14 bytes), EtherIP header,
  tunnel lookup, tunnel admin state.
- The tunnel interface has a random locally administered MAC address
  (`02:fe:xx:xx:xx:xx`) and a software MTU of 9000.
- RX counters are incremented by the decap nodes (`etherip4-input`,
  `etherip6-input`) and TX counters by `etherip-encap`.

## Origin and compatibility

The code was written in the VPP tree as `src/plugins/etherip/` and
`test/test_etherip.py` (branch `etherip` of ryskn/vpp-etherip, commit
`ecdc6c65d`, on top of FD.io VPP master `5b0c637e1`). `etherip/` in this
repository is that directory without changes, so it can be built either
against an installed VPP or inside a VPP tree.

Supported VPP version: **`stable/2606` (VPP 26.06)**. The CI builds and
tests the plugin against this branch, and this job must pass.

VPP master is not supported. Since VPP master commit `9c6b61f4b9` ("vnet:
use hidden visibility with explicit exports"), libvnet does not export
`vnet_feature_modify_end_node`, which the plugin calls, so the plugin does
not work on VPP master: it builds, but VPP exits with
`undefined symbol: vnet_feature_modify_end_node` when the plugin creates the
first tunnel, and inside a VPP tree `make build` fails in the
`check-vnet-exports` step for the same symbol.

The CI also runs against VPP master and allows that job to fail
(see [CI](#ci)).

## Repository layout

```
CMakeLists.txt        out-of-tree build (find_package(VPP))
etherip/              the plugin, identical to src/plugins/etherip/ in a VPP tree
test/test_etherip.py  tests for the VPP test framework (make test)
.github/workflows/    CI
```

## Building

### Out-of-tree build against an installed VPP

Requirements: an installed VPP with its development files, CMake 3.19 or
later, Ninja or make, a C compiler (VPP uses clang by default) and Python 3
with `ply` (for `vppapigen`).

The development files come from either

- the `vpp-dev` package (VPP headers, `vppapigen` and
  `lib/<multiarch>/cmake/vpp/VPPConfig.cmake` under `/usr`), or
- the install prefix of a VPP build tree, written by `make build` (debug) or
  `make build-release`:

  | VPP build            | install prefix                                  | `CMAKE_BUILD_TYPE` |
  |----------------------|-------------------------------------------------|--------------------|
  | `make build`         | `<vpp>/build-root/install-vpp_debug-native/vpp` | `Debug`            |
  | `make build-release` | `<vpp>/build-root/install-vpp-native/vpp`       | `Release`          |
  | packages (`vpp-dev`) | `/usr`                                          | `Release`          |

`CMAKE_BUILD_TYPE` must match the build type of the VPP that loads the
plugin. `Debug` defines `CLIB_DEBUG`, as the VPP tree does for debug builds,
and `CLIB_DEBUG` changes the values of `vnet_link_t` and the layout of
`clib_spinlock_t`. A plugin built with the wrong build type is loaded by VPP
but does not work correctly.

Example against a debug build tree:

```sh
VPP_PREFIX=$HOME/vpp/build-root/install-vpp_debug-native/vpp

cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH="$VPP_PREFIX" \
  -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build
cmake --install build
```

With the `vpp-dev` package installed, `CMAKE_PREFIX_PATH` is not needed:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
sudo cmake --install build
```

`cmake --install` writes (`<libdir>` is the library directory of the VPP
install, for example `lib/x86_64-linux-gnu` on Debian and Ubuntu):

- `<prefix>/<libdir>/vpp_plugins/etherip_plugin.so`: the plugin
- `<prefix>/<libdir>/vat2_plugins/etherip_test_plugin_etherip_plugin.so`: the vat2 plugin
- `<prefix>/share/vpp/api/plugins/etherip.api.json`: the API definition for
  VPP API clients (vpp_papi)
- `<prefix>/include/vpp_plugins/etherip/`: the plugin and API headers
- `<prefix>/include/vapi/etherip.api.vapi.h`, `etherip.api.vapi.hpp`: the
  VAPI C and C++ headers

With `CMAKE_INSTALL_PREFIX` set to the VPP install prefix (`/usr` for
packages), VPP finds the plugin in its default plugin directory. Otherwise,
add the directory to the `plugins` section of `startup.conf`:

```
plugins {
  add-path /path/to/install/lib/x86_64-linux-gnu/vpp_plugins
}
```

VPP loads only one plugin with a given file name, so do not install this
plugin into a VPP that already contains another `etherip_plugin.so`.

### Building inside a VPP tree

Copy `etherip/` into the VPP tree and build VPP as usual:

```sh
cp -R etherip $HOME/vpp/src/plugins/etherip
cd $HOME/vpp
make build          # or make build-release
```

`make build` runs CMake again because a new `CMakeLists.txt` is newer than
the last configure, and `src/plugins/CMakeLists.txt` adds every directory in
`src/plugins/` that has a `CMakeLists.txt`.

## Testing

`test/test_etherip.py` runs in the VPP test framework of a VPP tree. The
`EXTERN_*` variables of `make test` add the test directory, the plugin
directory and the API JSON directory of the out-of-tree build. After a debug
out-of-tree build installed to `$PWD/install` as above:

```sh
PLUGIN=$PWD              # this repository
cd $HOME/vpp             # the VPP tree used for the build (make build)
make test-debug TEST=test_etherip \
  EXTERN_TESTS=$PLUGIN/test \
  EXTERN_PLUGINS=$PLUGIN/install/lib/x86_64-linux-gnu/vpp_plugins \
  EXTERN_APIDIR=$PLUGIN/install/share/vpp/api
```

- `EXTERN_TESTS` is passed as `--test-src-dir`: the test framework also
  searches this directory for `test_*.py`.
- `EXTERN_PLUGINS` is passed as `--extern-plugin-dir`: VPP is started with
  `plugins { add-path <dir> }`.
- `EXTERN_APIDIR` is passed as `--extern-apidir`: vpp_papi also loads the
  `*.api.json` files below this directory.

Use `make test` (release) instead of `make test-debug` for a plugin built
with `CMAKE_BUILD_TYPE=Release` against `make build-release`.

When the plugin is built inside the VPP tree, copy the test as well and run
`make test-debug TEST=test_etherip` without the `EXTERN_*` variables.

Expected result on `stable/2606` and on VPP master before `9c6b61f4b9`: 53
tests, 52 passed and 1 skipped. On later VPP master, the tests that create a
tunnel fail because VPP exits with an undefined symbol (see
[Origin and compatibility](#origin-and-compatibility)). The skipped test is
`test_rx_ip4_options`: VPP `ip4-input` sends IPv4 packets with options to
`ip4-options`, which punts them (except Router Alert + IGMP), so EtherIP
packets with an outer IPv4 header with options never reach
`etherip4-input`.

## CLI

```
create etherip tunnel src <addr> dst <addr> [instance <n>] [outer-table-id <id>]
                      [hop-limit <1-255>] [dscp <dscp>] [set-df] [del]
show etherip tunnel [<interface>]
set etherip allow (on|off)
show etherip allow
```

- `create etherip tunnel` creates `etherip<instance>`. Without `instance`,
  the lowest free instance number is used. `src` and `dst` must be of the same
  address family. `outer-table-id` is the FIB table of the outer header
  (default 0). `hop-limit` 0 or no value means 64. `del` deletes the tunnel
  with the same `src`, `dst` and `outer-table-id`.
- `set etherip allow on` accepts received EtherIP packets (default: off).

Example: an L2 cross-connect between `GigabitEthernet0/8/0` and an EtherIP
tunnel.

```
set etherip allow on
create etherip tunnel src 192.0.2.1 dst 198.51.100.1
set interface state etherip0 up
set interface l2 xconnect GigabitEthernet0/8/0 etherip0
set interface l2 xconnect etherip0 GigabitEthernet0/8/0
```

To use a bridge domain instead: `set interface l2 bridge etherip0 <bd-id>`.

## Binary API

Defined in [`etherip/etherip.api`](etherip/etherip.api):

| message | description |
|---|---|
| `etherip_tunnel_add_del` | Create (`is_add` true) or delete a tunnel. The reply has the `sw_if_index` of the tunnel. A tunnel is deleted by matching `src`, `dst` and `outer_table_id`. |
| `etherip_tunnel_dump` / `etherip_tunnel_details` | Dump all tunnels (`sw_if_index` ~0) or one tunnel. `hop_limit` in the details is the effective value (64 for a tunnel created with 0). |
| `etherip_set_allow` | Accept (`enable` true) or refuse received EtherIP packets. |
| `etherip_get_allow` | Get the receive policy. |

`vl_api_etherip_tunnel_t` has `instance` (~0: allocate), `src`, `dst`,
`outer_table_id`, `sw_if_index` (details only), `hop_limit` (0: 64), `dscp`
and `set_df`.

## Known limitations

Same as the `missing` list in [`etherip/FEATURE.yaml`](etherip/FEATURE.yaml):

- GSO frames are not supported. Enable GSO segmentation on the tunnel
  interface instead: `set interface feature gso <interface> enable`.
- When VPP fragments the outer packet, the fragments carry the configured
  TTL / hop limit minus one, because IP fragmentation does not copy the
  locally originated flag to the fragments.
- Chained buffers whose first segment does not hold the outer header and 16
  more bytes are dropped as too short.
- IPv4 outer packets with IP options are not received, because `ip4-input`
  punts them before they reach the EtherIP input node.
- The pre-RFC header `0x03 0x00` is not accepted.
- ICMP fragmentation needed / IPv6 Packet Too Big messages are not handled.
- There is no receive policy exception for IPsec protected packets.
- DSCP, ECN and the flow label are not copied between the frame and the
  outer header.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on GitHub-hosted
`ubuntu-24.04` runners for pushes to `main`, pull requests, manual runs
(`workflow_dispatch`) and once a week (Monday 03:17 UTC), so that changes in
VPP that break the plugin are detected.

There is one job per VPP branch, `stable/2606` and `master`. The
`stable/2606` job is required: its failure fails the run. The `master` job is
marked `continue-on-error`, because VPP master is currently not supported
(see [Origin and compatibility](#origin-and-compatibility)), so its failure
does not fail the run. Each job:

1. checks out this repository and FD.io VPP at the branch, with history and
   tags (`src/scripts/version` uses `git describe`);
2. restores the ccache of the branch from the Actions cache;
3. runs `make UNATTENDED=y install-dep` and `make build` (debug, without
   the plugin);
4. builds the plugin out of tree (`CMAKE_BUILD_TYPE=Debug`,
   `CMAKE_PREFIX_PATH=vpp/build-root/install-vpp_debug-native/vpp`, the same
   compiler as VPP, `-Werror`), installs it to a staging prefix and runs
   `make test-debug TEST=test_etherip` with `EXTERN_TESTS`, `EXTERN_PLUGINS`
   and `EXTERN_APIDIR`;
5. copies `etherip/` to `vpp/src/plugins/etherip/` and runs `make build`
   again, to check that the plugin builds inside the VPP tree with the VPP
   compiler flags (`-Wall -Werror`); the tests are not run again;
6. on failure, uploads the build logs, the test log and `/tmp/vpp-unittest-*`
   as an artifact.

A job without ccache hits took 22 to 26 minutes in the first run, most of it
for the VPP build (`make build`: 20 to 24 minutes).

## License

Apache License 2.0, see [LICENSE](LICENSE). The plugin source files carry
`SPDX-License-Identifier: Apache-2.0`.
