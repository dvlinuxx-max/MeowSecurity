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
| Package Family Name | `MohammedAbdAlrahman.MeowSecurity_a2kxrh321s79p` |

Confirmed against Partner Center on 17 September 2026.

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

`allowElevation` is a restricted capability. A pre-approval request describing this design was
sent to `reportapp@microsoft.com` on 16 September 2026; the Store Certification team replied on
17 September 2026, and the answer changes the plan:

> All restricted capabilities are evaluated during the certification process. The
> `allowElevation` capability is generally not recommended […] In most cases, the use of this
> capability won't be approved. […] developers must provide comprehensive details explaining why
> they require this capability and why no alternative design or implementation would be
> sufficient. […] our team cannot guarantee approval.

**There is no separate pre-approval step to wait for.** The capability is judged during
certification, on the strength of a written justification submitted with the product, and it is
refused by default — so the justification is the whole of the case, not a formality.

That justification is [STORE-JUSTIFICATION.md](STORE-JUSTIFICATION.md), written against the five
points the certification team listed. It lives in the repository so it can serve as the public
URL they also require, and so every claim in it can be checked against the code.

The full justification is already saved in Partner Center, under **Supplemental info > Additional
Testing Information > Notes for Certification** — which is where the certification team reads it,
and which takes as much text as it needs. It covers all five of their points, the alternatives
that were rejected and why, the statement of assurance, and how to test the elevation path.

Where a short field asks for it instead, paste this and let it carry the link:

> Meow Security is an offline host intrusion detector. Three of its detections need privileges
> Windows withholds from a packaged app: a kernel ETW session, protected-process image paths, and
> machine-wide autorun control. Rather than elevate the app, they run in a separate helper started
> on demand behind the UAC prompt — it accepts five fixed verbs, executes no path it is given,
> admits only our own signed image over a user-only pipe, and exits with the app. Full
> justification: https://github.com/dvlinuxx-max/MeowSecurity/blob/main/STORE-JUSTIFICATION.md

If it is refused even so, the Store build silently loses live capture, per-process network
figures, protected-process inspection and machine-wide autorun control — a materially weaker
product than the GitHub one. That difference gets stated plainly on the Store listing rather than
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
