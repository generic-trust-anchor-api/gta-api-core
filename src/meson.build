# SPDX-FileCopyrightText: Copyright 2024 Siemens
#
# SPDX-License-Identifier: Apache-2.0

gta_framework_files = files (
  'gta_api.c',
)

gta_framework = static_library('gta_framework',
    gta_framework_files,
    include_directories : utils_include,
    dependencies : dep_gta_headers,
)
