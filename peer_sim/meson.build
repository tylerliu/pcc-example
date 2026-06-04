project('peer_sim', 'c', default_options: ['c_std=gnu11'])

arch = host_machine.cpu_family()
multiarch = arch == 'aarch64' ? 'aarch64-linux-gnu' : 'x86_64-linux-gnu'
dpdk_pc_dir = '/opt/mellanox/dpdk/lib' / multiarch / 'pkgconfig'

# Resolve libdpdk flags via pkg-config manually so we control PKG_CONFIG_PATH
pkg_config = find_program('pkg-config', required: true)

dpdk_cflags = run_command(pkg_config, '--cflags', 'libdpdk',
  env: {'PKG_CONFIG_PATH': dpdk_pc_dir}, check: true).stdout().strip().split()
dpdk_libs   = run_command(pkg_config, '--libs',   'libdpdk',
  env: {'PKG_CONFIG_PATH': dpdk_pc_dir}, check: true).stdout().strip().split()

dpdk  = declare_dependency(compile_args: dpdk_cflags, link_args: dpdk_libs)

sources = files(
  'main.c',
  'reflector.c',
)

executable('peer_sim', sources,
  dependencies: [dpdk],
  install: false,
)
