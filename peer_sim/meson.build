project('peer_sim', 'c', default_options: ['c_std=gnu11', 'warning_level=2'])

# peer_sim is built independently on each endpoint:
#   CX7: peer_sim --server ...
#   BF3: peer_sim --client ...
# The workload uses standard RDMA CM on both sides so mlx5 ECE negotiation
# selects the PCC algorithm slot for the BF3 sender QPs.
rdmacm_dep = dependency('librdmacm', required: true)
ibverbs_dep = dependency('libibverbs', required: true)

executable('peer_sim',
	'peer_sim.c',
	dependencies: [rdmacm_dep, ibverbs_dep],
	install: false,
)
