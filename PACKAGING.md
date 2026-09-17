# Store packaging

Reference values for building the MSIX package. They come from Partner Center and must
match exactly, or the package will not be accepted.

## Product identity

| Field | Value |
|---|---|
| Store ID (App ID) | `9MXL3CXWWLPJ` |
| `Package/Identity/Name` | `MohammedAbdAlrahman.MeowSecurity` |
| `Package/Identity/Publisher` | `CN=D81C7D5E-634A-451A-B6B5-3B12E63A7945` |
| `Package/Properties/PublisherDisplayName` | `Mohammed Abd Alrahman` |

The reservation expires if nothing is submitted within three months of 16 September 2026.

## The capability this package needs

The live capture, protected-process inspection and machine-wide autorun control run in
`MeowSecurity.Engine`, launched on demand with the `runas` verb. A packaged application may
not demand elevation for itself, so the manifest declares the restricted capability that
permits elevating a separate process:

```xml
<Package
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Capabilities>
    <rescap:Capability Name="allowElevation" />
  </Capabilities>
</Package>
```

`allowElevation` is a restricted capability: Microsoft has to approve its use before
submission. A pre-approval request describing this design was sent to
`reportapp@microsoft.com` on 16 September 2026.

**Nothing should be packaged for the Store until that answer arrives.** If it is refused, the
Store build would silently lose live capture, per-process network figures, protected-process
inspection and machine-wide autorun control — which would make it a materially weaker product
than the one published on GitHub, and that difference has to be stated plainly rather than
shipped quietly.

## Two builds, one codebase

| | Store (MSIX) | Direct download |
|---|---|---|
| Signing | Microsoft signs the package | unsigned for now — see below |
| Elevation | via the engine, pending `allowElevation` | via the engine, no approval needed |
| Updates | automatic | GitHub releases |

The same source produces both; only packaging and signing differ.

## Signing the direct download

There is no code-signing certificate for the GitHub build yet. An unsigned executable
means SmartScreen warns on first run until the download builds enough reputation, and
the publisher line reads "Unknown". Nothing about the product's behaviour changes.

Getting one means either paying for a commercial certificate, or qualifying for a free
open-source programme — and those ask for public traction (stars, forks, contributors,
outside write-ups) that this project has yet to build. The Store path is unaffected:
Microsoft signs the MSIX itself.
