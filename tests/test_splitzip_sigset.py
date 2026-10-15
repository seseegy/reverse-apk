"""`splitzip.unexpected_signature_entries`: himpunan berkas tanda tangan yang BOLEH ada pada keluaran apksigner (addendum #10), satu sumber kebenaran
untuk signer-daemon (pindaian keluaran split) dan `signer-selftest --check-bundle` (`sisa_ttd`).

Boleh: `META-INF/MANIFEST.MF`, paling banyak satu `<N>.SF`, paling banyak satu blok `<N>.RSA|DSA|EC`, dengan SATU `<N>`. Selain itu (dua nama dasar, dua blok,
`SIG-*`) = pelanggaran: SELURUH berkas tanda tangan dikembalikan, bukan sebagian.
"""

from __future__ import annotations

import pytest

from rvcore import splitzip

M = "META-INF/"


@pytest.mark.parametrize("names", [
    [],
    ["classes.dex", "AndroidManifest.xml"],
    [M + "MANIFEST.MF"],
    [M + "MANIFEST.MF", M + "OWNER.SF", M + "OWNER.RSA"],
    [M + "MANIFEST.MF", M + "OWNER.SF", M + "OWNER.EC"],
    [M + "MANIFEST.MF", M + "OWNER.SF", M + "OWNER.DSA"],
    [M + "OWNER.SF"],
    [M + "OWNER.RSA"],
    ["meta-inf/manifest.mf", "meta-inf/owner.sf", "META-INF/OWNER.rsa"],
    [M + "MANIFEST.MF", M + "OWNER.SF", M + "OWNER.RSA", M + "services/demo", M + "com.x.version", M + "app.kotlin_module", "assets/META-INF/X.RSA"],
])
def test_himpunan_boleh_tidak_dilaporkan(names):
    assert splitzip.unexpected_signature_entries(names) == []


@pytest.mark.parametrize("names", [
    [M + "MANIFEST.MF", M + "A.SF", M + "A.RSA", M + "B.SF", M + "B.RSA"],          # dua nama dasar
    [M + "OLD.RSA", M + "OWNER.SF", M + "OWNER.RSA"],                               # sisa v1 lama + baru
    [M + "OLD.SF", M + "OWNER.SF", M + "OWNER.RSA"],
    [M + "A.RSA", M + "B.RSA"],
    [M + "OWNER.RSA", M + "OWNER.DSA"],                                              # dua blok
    [M + "OWNER.RSA", M + "OWNER.EC"],
    [M + "OWNER.SF", M + "owner.sf"],                                                # dua .SF (beda huruf)
    [M + "MANIFEST.MF", M + "manifest.mf"],                                          # dua MANIFEST.MF
    [M + "SIG-FOO.SF"],
    [M + "SIG-FOO"],
    [M + "MANIFEST.MF", M + "OWNER.SF", M + "OWNER.RSA", M + "SIG-X"],
    [M + "OWNER.SF", M + "OTHER.RSA"],                                               # .SF dan blok beda nama dasar
])
def test_himpunan_pelanggar_dilaporkan_seluruhnya(names):
    got = splitzip.unexpected_signature_entries(names)
    assert got == [n for n in names if splitzip.is_signature_entry(n)] and got


def test_non_tanda_tangan_tidak_pernah_dilaporkan_walau_ada_pelanggaran():
    names = [M + "A.RSA", M + "B.RSA", "classes.dex", M + "services/x"]
    assert splitzip.unexpected_signature_entries(names) == [M + "A.RSA", M + "B.RSA"]
