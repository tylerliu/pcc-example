#
# Standalone DOCA Flow build for the pcc_example PCC-informed path-steering demo.
#
# Built independently on the BF3, not part of the top-level
# PCC/DPACC Meson build:
#
#   cd /home/tylerliu/pcc_example/doca-flow
#   meson setup build
#   ninja -C build
#   sudo ./build/doca_flow_steer --help
#
# The program runs on the BF3 eSwitch (switch,hws,isolated) and, on a p0<->p1
# DAC loopback, (a) classifies the sender's two RoCE QPs by QPN parity on
# egress, (b) optionally rewrites UDP dst 4791->4792 to mark a flow as moved to
# the other virtual path, then on wire ingress (c) CE-marks only native (4791)
# packets so CNP->QPN attribution stays coherent and (d) restores 4792->4791
# before delivering to the receiver SF. See README.md.
#

project('pcc_doca_flow', 'c',
	default_options: [
		'c_std=gnu11',
		'warning_level=2',
		'pkg_config_path=/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig',
	])

# DOCA Flow RoCE BTH match items and several actions used here are still tagged
# experimental in the 2.9/3.x headers.
add_project_arguments('-D', 'DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

deps = [
	dependency('libdpdk', required: true),
	dependency('doca-flow', required: true),
	dependency('doca-argp', required: true),
	dependency('doca-dpdk-bridge', required: true),
	dependency('doca-common', required: true),
]

# The steering pipeline as a reusable library so it can run standalone (below)
# or be embedded in the doca_pcc host process (see ../pcc).
steer_lib = static_library('steer',
	'steer.c',
	dependencies: deps,
	install: false,
)

executable('doca_flow_steer',
	'doca_flow_steer.c',
	dependencies: deps,
	link_with: steer_lib,
	install: false,
)
