# SPDX-License-Identifier: GPL-3.0-only
project('imsroha', 'c',
  version: '0.2.0',
  license: 'GPL-3.0-only',
  meson_version: '>= 1.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

add_project_arguments('-DIMSROHA_VERSION="@0@"'.format(meson.project_version()), language: 'c')

glib = dependency('glib-2.0')
gio = dependency('gio-2.0')
qmi = dependency('qmi-glib', version: '>= 1.36')
qrtr = dependency('qrtr-glib')
systemd = dependency('libsystemd')
alsa = dependency('alsa')
cc = meson.get_compiler('c')
amrwb = cc.find_library('opencore-amrwb')
amrnb = cc.find_library('opencore-amrnb')
amrwbenc = cc.find_library('vo-amrwbenc')

common = static_library('imsroha-common',
  'src/config.c', 'src/qmidev.c', 'src/rmnet_links.c',
  dependencies: [glib, gio, qmi, qrtr])

executable('imsroha',
  'src/imsroha.c', 'src/aka.c', 'src/sms.c', 'src/sip.c', 'src/dbus.c',
  'src/inbox.c', 'src/audio.c', 'src/codec.c', 'src/dns.c', 'src/ipsec.c', 'src/imei.c', 'src/amr_be.c',
  link_with: common,
  dependencies: [glib, gio, qmi, qrtr, systemd, amrwb, amrnb, amrwbenc],
  install: true)

# RCS: its own executable on the internet PDN; nothing above links it.
rcs_core = static_library('imsroha-rcs-core',
  'src/rcs/rcs_config.c', 'src/rcs/acs.c', 'src/rcs/http.c', 'src/rcs/net.c', 'src/rcs/smsport.c',
  'src/rcs/sipmsg.c', 'src/rcs/cpim.c', 'src/rcs/msrp.c',
  include_directories: include_directories('src'),
  link_with: common,
  dependencies: [glib, gio])
rcs_inc = include_directories('src', 'src/rcs')
resolv = cc.find_library('resolv', required: false)
executable('imsroha-rcs',
  'src/rcs/rcsd.c', 'src/rcs/rcs_dbus.c', 'src/rcs/sipua.c', 'src/rcs/chat.c', 'src/aka.c', 'src/imei.c',
  link_with: [rcs_core, common],
  include_directories: rcs_inc,
  dependencies: [glib, gio, qmi, qrtr, resolv],
  install: true)

executable('imsroha-bearer', 'src/imsroha_bearer.c',
  link_with: common,
  dependencies: [glib, gio, qmi, qrtr, systemd],
  install: true)

executable('imsroha-vss-samsung', 'src/vss_samsung.c',
  link_with: common,
  dependencies: [glib, gio, qmi, qrtr],
  install: true)

executable('imsroha-audio', 'src/imsroha_audio.c',
  dependencies: [alsa],
  install: true)

prefix = get_option('prefix')
unitdir = prefix / 'lib/systemd/system'
userunitdir = prefix / 'lib/systemd/user'
install_data('systemd/imsroha.service', 'systemd/imsroha-bearer.service',
  'systemd/imsroha-vss-samsung.service', install_dir: unitdir)
install_data('systemd/ModemManager.service.d/imsroha.conf',
  install_dir: unitdir / 'ModemManager.service.d')
install_data('systemd/imsroha-audio.service', install_dir: userunitdir)
install_symlink('imsroha-audio.service',
  pointing_to: '../imsroha-audio.service',
  install_dir: userunitdir / 'graphical-session.target.wants')
install_data('systemd/codes.noa.IMSroha.conf', 'systemd/codes.noa.IMSroha.Rcs.conf',
  install_dir: prefix / 'share/dbus-1/system.d')
install_data('systemd/imsroha-rcs.service', install_dir: unitdir)
install_data('data/carriers.conf', install_dir: prefix / 'share/imsroha')
install_data('data/imsroha.conf', install_dir: prefix / 'share/doc/imsroha',
  rename: 'imsroha.conf.example')
install_data('data/99-imsroha.rules', install_dir: prefix / 'lib/udev/rules.d')

golden = executable('sip-golden', 'tests/sip-golden.c', 'src/sms.c', 'src/dns.c', 'src/ipsec.c', 'src/imei.c', 'src/amr_be.c',
  link_with: common,
  c_args: ['-DGOLDEN_SRCDIR="@0@"'.format(meson.project_source_root()), '-Wno-unused-function'],
  include_directories: include_directories('src'),
  dependencies: [glib, gio, qmi, qrtr, systemd],
  build_by_default: false)
rmnet_clear = executable('rmnet-clear', 'tests/rmnet-clear.c', link_with: common,
  dependencies: [glib], build_by_default: false)
test('rmnet-clear', find_program('tests/rmnet-clear.sh'), args: [rmnet_clear.full_path()],
  depends: rmnet_clear)
test('amr-be', executable('amr-be', 'tests/amr-be.c', 'src/amr_be.c', build_by_default: false))
# LG U+ with tests/lguplus-recorded.conf: byte for byte what b2q-imsd sent.
test('sip-golden-lguplus-recorded', find_program('tests/run-golden.sh'),
  args: [golden.full_path(), meson.project_source_root() / 'tests/golden-lguplus.txt',
         meson.project_source_root() / 'tests/normalize.sh'],
  env: ['GOLDEN_CONF=' + meson.project_source_root() / 'tests/lguplus-recorded.conf'],
  depends: golden, is_parallel: false)
# LG U+ as configured: TTAK.KO-06.0357/R6 with sec-agree.
test('sip-golden-lguplus', find_program('tests/run-golden.sh'),
  args: [golden.full_path(), meson.project_source_root() / 'tests/golden-lguplus-tta.txt',
         meson.project_source_root() / 'tests/normalize.sh'],
  depends: golden, is_parallel: false)
test('sip-golden-kt', find_program('tests/run-golden.sh'),
  args: [golden.full_path(), meson.project_source_root() / 'tests/golden-kt.txt',
         meson.project_source_root() / 'tests/normalize.sh'],
  env: ['GOLDEN_CARRIER=KT'],
  depends: golden, is_parallel: false)
test('esp-loopback', find_program('tests/esp-loopback.sh'),
  args: [golden.full_path(), meson.project_source_root() / 'tests/golden-kt.txt',
         meson.project_source_root() / 'tests/normalize.sh'],
  depends: golden, is_parallel: false)

# RCS
test('rcs-smsport', executable('rcs-smsport', 'tests/rcs/smsport.c', link_with: rcs_core,
  include_directories: rcs_inc, dependencies: [glib], build_by_default: false))
rcs_acs_request = executable('rcs-acs-request', 'tests/rcs/acs-request.c', link_with: rcs_core,
  c_args: ['-DGOLDEN_SRCDIR="@0@"'.format(meson.project_source_root())],
  include_directories: rcs_inc, dependencies: [glib, gio, qmi, qrtr], build_by_default: false)
test('rcs-acs-request', find_program('tests/run-golden.sh'),
  args: [rcs_acs_request.full_path(), meson.project_source_root() / 'tests/rcs/golden-acs-lguplus.txt',
         find_program('cat').full_path()],
  depends: rcs_acs_request)
rcs_acs_flow = executable('rcs-acs-flow', 'tests/rcs/acs-flow.c', link_with: rcs_core,
  include_directories: rcs_inc, dependencies: [glib, gio, qmi, qrtr], build_by_default: false)
test('rcs-acs-flow', find_program('tests/rcs/acs-flow.sh'),
  args: [rcs_acs_flow.full_path(), meson.project_source_root()], depends: rcs_acs_flow,
  is_parallel: false, timeout: 120)
rcs_client = executable('rcs-client', 'tests/rcs/rcs-client.c', dependencies: [glib, gio],
  build_by_default: false)
test('rcs-daemon', find_program('tests/rcs/daemon.sh'),
  args: [meson.project_build_root() / 'imsroha-rcs', rcs_client.full_path(), meson.project_source_root()],
  depends: [rcs_client], is_parallel: false, timeout: 120)
