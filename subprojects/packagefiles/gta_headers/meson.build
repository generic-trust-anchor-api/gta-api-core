#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024, Siemens AG
#
#;**********************************************************************;

# Global project definition for GTA API implementation
project('Generic Trust Anchor API header files',
    ['c'],
    version: '1.0'
)


# Global include files for GTA API
libgta_include = include_directories('./')

# Header files to be installed with "install" target
install_headers(
   './gta_apif.h',
   './gta_errinfo.h',
   './gta_secmem.h',
   './gta_api.h',
   './gta_handle.h',
   './gta_stream.h',
   './gta_psync.h',
   subdir : 'gta_api'
)

gta_header_dep = declare_dependency(
  include_directories : libgta_include,
)
