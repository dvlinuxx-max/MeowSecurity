using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MeowSecurity.Core.Native;

namespace MeowSecurity.Core.Processes;

/// <summary>
/// Trust verdict from WinVerifyTrust (embedded + catalog), plus a best-effort publisher
/// name. An unsigned binary is not proof of malware, but for something running from a
/// user-writable location it raises the score.
/// </summary>
internal static class Signing
{
    public static (SignatureState state, string? publisher) Check(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            return (SignatureState.Unknown, null);

        var state = WinTrust.Verify(imagePath) switch
        {
            WinTrust.Result.Trusted => SignatureState.SignedValid,
            WinTrust.Result.NoSignature => SignatureState.Unsigned,
            _ => SignatureState.SignedInvalid,
        };

        return (state, PublisherName(imagePath));
    }

    // The publisher comes from the embedded certificate when there is one. Catalog-signed
    // system files have no embedded cert, so this returns null for them — the trust state
    // from WinVerifyTrust is what actually matters.
    private static string? PublisherName(string imagePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(imagePath));
#pragma warning restore SYSLIB0057
            var name = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch
        {
            return null;
        }
    }
}
