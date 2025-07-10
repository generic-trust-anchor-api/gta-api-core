#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

gta_utils_files = files (
  'gta_list.c',
  'gta_memset.c',
)

# Header files to be installed with "install" target
install_headers(
   './gta_memset.h',
   './gta_list.h',
   subdir : 'gta_api/util'
)

gta_utils = static_library('gta_utils',
    gta_utils_files,
    dependencies : dep_gta_headers,
    install : true,
)

