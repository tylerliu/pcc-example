#
# Copyright (c) 2021-2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice, this list of
#       conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
#       to endorse or promote products derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

project('DOCA_APPLICATIONS', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'), ('VERSION'), check: true).stdout().strip(),
	license: 'BSD-3',
	default_options: [
		'buildtype=debug',
		'cpp_std=c++11',
		'pkg_config_path=/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig'
	],
	meson_version: '>= 0.61.2'
)

DOCA_PREFIX = 'doca_'

#################################
# Basic Compilation Definitions #
#################################

languages = ['c', 'cpp']

base_c_args = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
]

base_cpp_args = [
	'-Wno-missing-field-initializers',
]

install_apps = false
app_install_dir = ''

################
# DOCA Drivers #
################

doca_name_to_pkgconfig_name = {
	'dpdk': 'libdpdk',
	'flexio': 'libflexio',
	'ucx': 'ucx',
}

# DPACC Support
flag_enable_dpa_support = true
dpacc_mcpu_flag = get_option('dpacc_mcpu')
dpacc_dependencies = ['dpa', 'pcc', 'flexio']
dpacc = find_program('dpacc', dirs: ['/opt/mellanox/doca/tools'], required: false)
if not dpacc.found()
	warning('Missing DPACC tool needed by DOCA DPA, DOCA PCC and FlexIO')
	flag_enable_dpa_support = false
endif
if get_option('enable_cross_compilation_to_dpu')
	warning('DPACC tool is not support during cross compilation')
	flag_enable_dpa_support = false
endif

##############################
# Advanced Compilation Flags #
##############################

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: languages)

if get_option('enable_deprecated_features')
	# Comment this line to restore warnings of deprecated DOCA features
	add_project_arguments('-D DOCA_ALLOW_DEPRECATED_API', language: languages)
endif

if get_option('enable_trace_log')
	add_project_arguments('-D DOCA_LOGGING_ALLOW_TRACE', language: languages)
endif

if get_option('enable_cross_compilation_to_dpu')
	# Please update this folder if the base cross-compilation folder is located elsewhere
	add_project_arguments('-I/root/doca-cross/usr/include', language: languages)
endif

# Resolve irrelevant compiler warnings
add_project_arguments('-Wno-format-zero-length', language: languages)

base_app_dependencies = []
base_app_dependencies += dependency('threads')

# In old distributions it was in libbsd, in newer ones it is part of libc
c_compiler = meson.get_compiler('c')
if c_compiler.has_function('strlcpy', prefix: '#include <string.h>', args: ['-D_GNU_SOURCE'])
	add_project_arguments('-D DOCA_USE_LIBC_STRING_L_FUNC', language: languages)
else
	dependency_libbsd = dependency('libbsd', required: false)
	if dependency_libbsd.found()
		base_app_dependencies += dependency_libbsd
		add_project_arguments('-D DOCA_USE_LIBBSD', language: languages)
		# Ensure mlnx-dpdk will manage to find our libbsd if exists
		add_project_arguments('-D RTE_USE_LIBBSD', language: languages)
	endif
endif

common_path = 'common'
base_app_inc_dirs = [
	include_directories(common_path),
]

APP_NAME = 'pcc'

fs = import('fs')

# Basic app definitions
app_dependencies = base_app_dependencies
app_doca_dependencies = []
app_driver_dependencies = []
app_doca_depends = []
app_driver_depends = []
app_inc_dirs = base_app_inc_dirs

######################################
# Check dependencies before starting #
######################################

if fs.is_dir(APP_NAME + '/' + 'dependencies')
	subdir(APP_NAME + '/' + 'dependencies')
endif

# Everything should use common (no need for all apps to add it manually)
app_doca_depends += 'common'

# DOCA Libraries
foreach doca_dep : app_doca_depends
	cur_dep = dependency('doca-' + doca_dep.replace('_', '-'), required: true)
	# DPA Check
	if not flag_enable_dpa_support and dpacc_dependencies.contains(doca_dep)
		error('Missing DPACC support for @0@'.format(doca_dep))
	endif
	app_doca_dependencies += cur_dep
endforeach

# DOCA Drivers
foreach driver_dep : app_driver_depends
	cur_dep = dependency(doca_name_to_pkgconfig_name[driver_dep], required: true)
	# DPA Check
	if not flag_enable_dpa_support and dpacc_dependencies.contains(driver_dep)
		error('Missing DPACC support for @0@'.format(driver_dep))
	endif
	app_driver_dependencies += cur_dep
endforeach

# Pass on the new information
app_dependencies += app_doca_dependencies
app_dependencies += app_driver_dependencies

#########################
# Build the Application #
#########################

# Enter the application's directory
subdir(APP_NAME)
