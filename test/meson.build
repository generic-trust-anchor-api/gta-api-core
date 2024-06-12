#;**********************************************************************;
# SPDX-License-Identifier: MPL-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

# Files depend on host OS
if target_os == 'linux'
  gta_test_framework_files = files (
    'test_framework.c',
    meson.project_source_root() + '/platform/gta_linux.c',
  )

elif target_os == 'windows'
  gta_test_framework_files = files (
    'test_framework.c',
    meson.project_source_root() + '/platform/gta_windows.c',
  )

else
  gta_test_framework_files = files (
    'test_framework.c',
  )
endif

gta_test_framework = executable(
    'gta_test_framework',
    gta_test_framework_files,
    include_directories : [platform_include, utils_include,],
    dependencies : [ dep_cmocka,
                     dep_gta_headers,
                   ],
    link_with : [ libgta_static,
                  unittest_gta_provider_static,
                ],
)

test_output_dir = 'CMOCKA_XML_FILE=' + meson.current_build_dir() + '/%g.xml'

test(
    'gta_test_framework',
    gta_test_framework,
    env: [ test_output_dir,
           'CMOCKA_MESSAGE_OUTPUT=XML',
     ],
)

