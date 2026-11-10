# Maintainer: Noa Himesaka <himesaka@noa.codes>
# SPDX-License-Identifier: MIT
#
# ModemManager 1.24.2 for the b2q aarch64 rootfs with the b2q IMS backend, the
# bearer-count crash fix, IMS DTMF and the kept IPA QMAP path from this directory
# (see README.md; 0002 is kept for reference and not applied).
#
# Build on the phone as the unprivileged `build` user, from this directory:
#
#   su build -c 'cd /home/build/modmgr-links && makepkg -s --noconfirm'
#
# Then install the resulting package as root with `pacman -U`. pkgrel is above
# the ports repo's and above the previous local build, so this build wins.

pkgname=modemmanager
pkgver=1.24.2
pkgrel=12
pkgdesc="Mobile broadband modem management service with b2q IMS support"
url="https://www.freedesktop.org/wiki/Software/ModemManager/"
arch=(aarch64)
license=(GPL-2.0-or-later)
depends=(
  bash
  glib2
  glibc
  hicolor-icon-theme
  libgcc
  libgudev
  libmbim
  libqmi
  libqrtr-glib
  mobile-broadband-provider-info
  polkit
  ppp
  systemd-libs
  libmm-glib
)
makedepends=(
  bash-completion
  git
  glib2-devel
  gobject-introspection
  meson
  systemd
)
source=(
  "git+https://gitlab.freedesktop.org/mobile-broadband/ModemManager.git#tag=${pkgver}"
  "0001-broadband-modem-qmi-add-b2q-imsd-backend-for-voice-a.patch"
  "0003-iface-modem-do-not-abort-when-the-bearer-count-exceeds.patch"
  "0004-call-ims-send-DTMF-through-b2q-imsd.patch"
  "0005-port-qmi-keep-the-IPA-QMAP-data-path-when-another-PDN.patch"
  "99-b2q-ims.rules"
)
b2sums=(
  'SKIP'
  '1de21071ec6c46ee006b15a93c44d43739ee92263e10a71d5c71d2211f63756ef1a1fe98ef900ba752f18fa9b71966a1e284d24524ad830628a4efce90788e4d'
  '24bb2494310c45f5ef27a447e8530375741daf32f20f3c396d281143b44e93a6b1d85b3f65e28520f5ac0a115142d33a94877612db9a2dd7e8d3a2075bfef3bf'
  'c3dd4b0417a7a0c782b1c1e79ef57310df7679a07d6804736d59467ca0049ebf0e7b3ac89f0397bedf04658c31e3d6bef6cc2b49d54a6d7172bded0bc7721f3c'
  'd162faa797e009321544fe0de0550d3eea4bdb7071f9636f71286abab64c9a576e586c9465ce4b5f2968abaec584a70a46887c0526dcb33a77fde563c72d0737'
  '0130853c9a69fd39f8d159e1964dea4f82ae21ccefea5e0f8a7b4d9d92d6fc626b182fc07490df1f1831d6a82539408231d168dd59dd99ba02f24427e036bde4'
)

prepare() {
  cd ModemManager
  git apply "$srcdir/0001-broadband-modem-qmi-add-b2q-imsd-backend-for-voice-a.patch"
  git apply "$srcdir/0003-iface-modem-do-not-abort-when-the-bearer-count-exceeds.patch"
  git apply "$srcdir/0004-call-ims-send-DTMF-through-b2q-imsd.patch"
  git apply "$srcdir/0005-port-qmi-keep-the-IPA-QMAP-data-path-when-another-PDN.patch"
}

build() {
  local meson_options=(
    -D dbus_policy_dir=/usr/share/dbus-1/system.d
    -D dist_version="\"$pkgver-$pkgrel\""
    -D gtk_doc=false
    -D vapi=false
    -D polkit=permissive
  )

  arch-meson ModemManager build "${meson_options[@]}"
  meson compile -C build
}

package() {
  meson install -C build --destdir "$pkgdir"

  # Keep libmm-glib files out so there are no conflicts with libmm-glib package
  rm -rf "$pkgdir"/usr/include
  rm -rf "$pkgdir"/usr/lib/pkgconfig
  rm -rf "$pkgdir"/usr/lib/libmm-glib.so*
  rm -rf "$pkgdir"/usr/lib/girepository-1.0
  rm -rf "$pkgdir"/usr/share/gir-1.0

  install -Dm644 "$srcdir/99-b2q-ims.rules" "$pkgdir/usr/lib/udev/rules.d/99-b2q-ims.rules"
}
