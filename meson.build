project('u2fhid2bt', [ 'c', 'cpp' ])

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

libsystemd = dependency('libsystemd', version: '>=237')
systemd = dependency('systemd', version: '>=237')
libhidapi = dependency('hidapi-hidraw')



u2fhid2bt = executable('u2fhid2bt',
    'gatt.c',
    'gatt.h',
    'main.c',
    'uhid.c',
    'uhid.h',
    'u2f.c',
    'u2f.h',
    dependencies: libsystemd,
    install_dir: get_option('libexecdir'),
    install: true
)

bluez = executable('bluez',
    'test/bluez.c',
    'u2f.c',
    'u2f.h',
    dependencies: libsystemd
)

list = executable('list',
    'test/list.c',
    dependencies: libhidapi
)

hidtest = executable('hidtest',
    'test/u2f-tests/u2f_util.cc',
    'test/u2f-tests/u2f_util.h',
    'test/u2f-tests/HIDTest.cc',
    'test/u2f-tests/u2f_hid.h',
    'test/u2f-tests/u2f.h',
    dependencies: libhidapi
)

cd = configuration_data()
cd.set('libexecdir', get_option('prefix') + '/' + get_option('libexecdir'))
configure_file(
    install_dir: systemd.get_pkgconfig_variable('systemdsystemunitdir'),
    configuration: cd,
    input: 'u2fhid2bt.service.in',
    output: 'u2fhid2bt.service',
)

test('tests', find_program('test/runtests'))
