# Building and testing the Store package

```
python msix/build_msix.py
```

Produces `msix/out/MeowSecurity_<version>_x64.msix`, around 67 MB. The identity values are
baked into `build_msix.py` from Partner Center and are recorded in [PACKAGING.md](../PACKAGING.md);
they must match exactly or the upload is rejected.

The package is **unsigned on purpose** — the Store signs it. Do not sign it yourself.

## Testing it before uploading

The certificate dance is avoidable. With Developer Mode already on, the layout can be
registered as a package directly, with no signing and nothing added to the certificate store:

```powershell
Add-AppxPackage -Register "$env:TEMP\meow_msix\layout\AppxManifest.xml"
```

Launch it the way Windows will:

```powershell
$pfn = (Get-AppxPackage -Name MohammedAbdAlrahman.MeowSecurity).PackageFamilyName
Start-Process "shell:AppsFolder\$pfn!MeowSecurity"
```

Remove it again:

```powershell
Remove-AppxPackage -Package (Get-AppxPackage -Name MohammedAbdAlrahman.MeowSecurity).PackageFullName
```

## What has been verified, and what has not

Verified on 17 September 2026:

- The package builds and registers.
- It launches under its package identity and the window comes up.
- It writes to the real `%LOCALAPPDATA%\MeowSecurity`, not a redirected container path — so a
  person moving between the Store build and the GitHub build keeps their settings and their
  event history. This is the full-trust behaviour on Windows 1903 and above, which is why the
  manifest sets that as the minimum.
- The manifest's identity matches Partner Center exactly, including the package family name.

**Not yet verified: the elevation path.** Starting the engine raises a UAC consent prompt, and
a prompt has to be answered by a person. Until somebody has done that inside the packaged
build, we do not actually know that `allowElevation` behaves as designed here — and that is the
one thing the whole submission turns on.

To check it, in the packaged app: open **Settings** and start the live capture, or go to
**Autoruns** and switch a machine-wide entry on or off. Expect the Windows consent prompt, and
then live process rows appearing as programs start. If it fails instead, the reason is written
to `%LOCALAPPDATA%\MeowSecurity\engine.log` — `refused a client` there means the helper's
identity check did not recognise the packaged application's image path, which would be a real
bug and not a packaging detail.

## Why the publish is not single-file

The three executables are published self-contained into one folder, without
`PublishSingleFile`. Three single-file publishes would embed three separate copies of the .NET
runtime; sharing one folder costs about a third of the size, which the Store pays for and so
does everyone who installs it.

`SatelliteResourceLanguages=en` strips .NET's own framework messages in the twelve other
languages it ships. Left in, MakePri indexes them and the package claims to support languages
this product does not speak — and Store policy expects a listing's language to be the app's.
This application says everything it says through its own string table, in Arabic and English.
