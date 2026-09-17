# Vendored front-end dependencies

The dashboard serves its JavaScript from this directory instead of a CDN, so a
visitor's browser executes no third-party script and the Content-Security-Policy
can restrict `script-src` to this origin.

| File | Package | Source | SHA-256 |
|---|---|---|---|
| `chart-4.4.0.umd.js` | chart.js 4.4.0 (MIT) | `dist/chart.umd.js` from the npm tarball | `321e3a3fa98da4aaa957d10be57cbb514de0989eed8f9d726b5d05902cd01904` |

The file is byte-identical to the one in the published package, so it can be
verified independently:

```bash
npm pack chart.js@4.4.0 && tar -xzf chart.js-4.4.0.tgz
sha256sum package/dist/chart.umd.js static/vendor/chart-4.4.0.umd.js
```

`tests/test_hardening.py` pins the checksum above, so a modified file fails the
suite. To upgrade, replace the file, update this table and the test together.

chartjs-plugin-annotation was previously loaded from a CDN but never used by
any chart, so it was removed rather than vendored.
