project('u2ftest', 'c')

libsystemd = dependency('libsystemd', version: '>=221')

executable(
    'u2fhid2bt',
    'core.c',
    'core.h',
    'list.c',
    'list.h',
    'main.c',
    'misc.h',
    'u2f.h',
    dependencies: libsystemd
)
