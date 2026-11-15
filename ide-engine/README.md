# SANA IDE — Code-OSS Engine

This directory records the pinned upstream engine baseline and the SANA distribution boundary.

## Pinned upstream

- Upstream: https://github.com/microsoft/vscode
- Upstream tag: 1.146.0
- Upstream commit: 69047191fc427f2f92828279aae1d90d8eeda7ab
- Upstream license: MIT (retain upstream notices and third-party notices)

The SANA IDE product is intended to be a distribution built from Code-OSS/Electron, not a React/Monaco imitation or a WebView embedding. The existing Tauri V1 application remains untouched in `Xx505xX505/sana-v1`.

## Product customization boundary

SANA-specific product metadata belongs in `product.json` in the upstream Code-OSS source checkout. Do not change upstream source files outside this working checkout.

Initial SANA identity values (to be applied in the dedicated engine checkout):
- Product short name: SANA
- Product long name: SANA IDE
- Application executable name: sana
- User data folder: .sana
- Shared user data folder: .sana-shared
- Windows directory / registry names: SANA IDE / SANA
- URL protocol: sana
- Update service: disabled until SANA has a signed update service
- Extension gallery: do not use Microsoft's Visual Studio Marketplace without explicit permission; choose a compatible gallery or SANA-managed gallery.

Every Windows application ID, mutex, protocol and registration identifier must be unique to SANA and verified before installer packaging.

## Source checkout instructions

Clone upstream into a separate local checkout, then pin the exact commit:

```powershell
git clone https://github.com/microsoft/vscode.git sana-code-oss-source
cd sana-code-oss-source
git checkout --detach 69047191fc427f2f92828279aae1d90d8eeda7ab
```

Do not copy the entire upstream source tree into this repository. Keep upstream as its own Git checkout so upstream merges and licensing remain manageable.

## Build baseline

The pinned source declares Node.js 24.22.1 in `.nvmrc` and pnpm 12.16.0 in `package.json`. Use those exact versions for reproducible work. The user's reported environment has Node 24.11.0 and a broken Corepack/pnpm shim, so a clean dependency install/build has not yet been demonstrated.

For Windows, complete the documented Visual Studio C++ Build Tools and Windows SDK requirements before building native modules. The user's environment scan reported missing Windows SDK files (`Windows.h`, `kernel32.lib`, `rc.exe`); recheck after installing the required components.

## First engineering milestone

1. Establish a clean, pinned upstream checkout.
2. Apply only SANA distribution metadata and branding assets.
3. Produce and run an unmodified baseline Windows Code-OSS build.
4. Produce and run the SANA-branded build.
5. Only then port V1 behavior and integrate the SANA licensing client.

No successful build is claimed by this document.