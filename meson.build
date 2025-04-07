#;**********************************************************************;
# SPDX-License-Identifier: MPL-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

# Global project definition for GTA API implementation
project('Generic Trust Anchor API Core',
    ['c'],
    default_options : [     # TODO can be overwritten by override_options in specific build targets
        'c_std=gnu99',      # TODO building openssl requires gnu extensions, setting it in "subproject" does not work
        'warning_level=3',  # highest warning level
        'buildtype=plain',
    ],
    license: 'MPL 2.0',
    meson_version: '>=0.56.0',
    version: '0.1'
)

# Specify global compiler options
c_compiler = meson.get_compiler('c')
add_project_arguments(
  c_compiler.get_supported_arguments(
     '-Wextra',
     '-Wpedantic',
     '-Wno-unused-function',  # TODO check if suppressing this warning is a good idea
     '-Wno-unused-parameter', # TODO check if suppressing this warning is a good idea
  ),
  language: 'c'
)

# Get custom build options from meson_options.txt
build_type = get_option('build')
build_dep = get_option('build-dependencies')

# TODO consider to use more generic override_options for build targets
if build_type == 'release'
add_project_arguments(
   c_compiler.get_supported_arguments(
      '-O2',
   ),
   language: 'c'
)
elif build_type == 'debug'
add_project_arguments(
   c_compiler.get_supported_arguments(
      '-O0',
      '-g',
   ),
   language: 'c'
)
endif

# Get target OS
target_os = host_machine.system()
if target_os == 'linux'
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DLINUX',
   ),
   language: 'c'
)
elif target_os == 'windows'
   add_project_arguments(
   c_compiler.get_supported_arguments(
      '-DWINDOWS',
   ),
   language: 'c'
)
endif

# Global include files for headers
utils_include = include_directories('./util/')
platform_include = include_directories('./platform/')

# External dependencies
gta_headers_proj = subproject('gta_headers')
dep_gta_headers = gta_headers_proj.get_variable('gta_header_dep')

if build_dep
   cmocka_proj    = subproject('cmocka')
   dep_cmocka     = cmocka_proj.get_variable('cmocka_dep')
else
   dep_cmocka    = dependency('cmocka')
endif

subdir('src')       # Compile framework code as static library
subdir('util')      # Compile support code as static library
subdir('test/unittest_gta_provider') # Compile unittest provider needed for framework tests


libgta_static = static_library('gta',
    link_whole: [ gta_framework,
                  gta_utils,
                ],
    install: true
)

libgta_shared = shared_library('gta',
    link_whole: [ gta_framework,
                  gta_utils,
                ],
    install: true
)

pkg = import('pkgconfig')
pkg.generate(libraries : [libgta_static ],
             version : meson.project_version(),
             name : 'libgta',
             description : 'Generic Trust Anchor API Core')


# Build and call tests
subdir('test')

# Looking for Valgrind
prog_valgrind = find_program('valgrind', required: false)
if prog_valgrind.found()
   # Run valgrind memory leakage test
   run_target('gta_framework_memcheck',
      command: [prog_valgrind, '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--error-exitcode=99', '--errors-for-leak-kinds=all', gta_test_framework.full_path()],
      depends: [gta_test_framework],
   )
endif
