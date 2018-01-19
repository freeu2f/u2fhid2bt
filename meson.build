project('u2fhid2bt', 'c')

add_project_arguments([
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Wstrict-aliasing',
    '-Wchar-subscripts',
    '-Wformat-security',
    '-Wmissing-declarations',
    '-Wmissing-prototypes',
    '-Wnested-externs',
    '-Wpointer-arith',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wtype-limits',
    '-Wunused-function',
    '-Wno-missing-field-initializers',
    '-Wno-unused-command-line-argument',
    '-Wno-unused-parameter',
    '-Wno-unknown-pragmas',
    '-Wno-sign-compare',
], language: 'c')

libsystemd = dependency('libsystemd', version: '>=221')

executable('u2fhid2bt',
    'list.c',
    'list.h',
    'uhid.c',
    'uhid.h',
    'gatt.c',
    'gatt.h',
    'main.c',
    'u2f.c',
    'u2f.h',
    dependencies: libsystemd
)
