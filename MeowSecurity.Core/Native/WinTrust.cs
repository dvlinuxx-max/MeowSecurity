using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>
/// Authoritative Authenticode verification via the WinTrust API — the same path Windows
/// itself uses. It handles both embedded signatures and catalog-signed system binaries
/// (most of System32 is catalog-signed, which a naive X509 chain build mis-reports).
/// </summary>
internal static class WinTrust
{
    private static Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;

    public enum Result { NoSignature, Trusted, Untrusted }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll")]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr hCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr template);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    public static Result Verify(string path)
    {
        uint status = VerifyEmbedded(path);
        if (status == 0) return Result.Trusted;
        if (status is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
            return VerifyCatalog(path); // most of System32 lives here
        return Result.Untrusted;
    }

    private static uint VerifyEmbedded(string path)
    {
        IntPtr pFile = IntPtr.Zero, pData = IntPtr.Zero, pPath = IntPtr.Zero;
        try
        {
            pPath = Marshal.StringToHGlobalUni(path);
            var file = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pPath,
            };
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(file, pFile, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pUnion = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            uint status = WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, pData);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, false);
            WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, pData);
            return status;
        }
        catch { return TRUST_E_NOSIGNATURE; }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
            if (pPath != IntPtr.Zero) Marshal.FreeHGlobal(pPath);
        }
    }

    private static Result VerifyCatalog(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero, hFile = IntPtr.Zero, hCatInfo = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                return Result.NoSignature;

            hFile = CreateFileW(path, 0x80000000, 0x1, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (hFile == new IntPtr(-1)) return Result.NoSignature;

            uint hashLen = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, null, 0);
            if (hashLen == 0) return Result.NoSignature;
            var hash = new byte[hashLen];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, hash, 0))
                return Result.NoSignature;

            IntPtr prev = IntPtr.Zero;
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, ref prev);
            if (hCatInfo == IntPtr.Zero) return Result.NoSignature; // not in any catalog

            var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                return Result.NoSignature;

            string memberTag = Convert.ToHexString(hash);
            return VerifyAgainstCatalog(path, catInfo.wszCatalogFile, memberTag) ? Result.Trusted : Result.Untrusted;
        }
        catch { return Result.NoSignature; }
        finally
        {
            if (hCatInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hFile != IntPtr.Zero && hFile != new IntPtr(-1)) CloseHandle(hFile);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static bool VerifyAgainstCatalog(string memberPath, string catalogFile, string memberTag)
    {
        IntPtr pCat = IntPtr.Zero, pData = IntPtr.Zero;
        IntPtr pCatPath = IntPtr.Zero, pMemberPath = IntPtr.Zero, pTag = IntPtr.Zero;
        try
        {
            pCatPath = Marshal.StringToHGlobalUni(catalogFile);
            pMemberPath = Marshal.StringToHGlobalUni(memberPath);
            pTag = Marshal.StringToHGlobalUni(memberTag);
            var cat = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = pCatPath,
                pcwszMemberFilePath = pMemberPath,
                pcwszMemberTag = pTag,
            };
            pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(cat, pCat, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pUnion = pCat,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            uint status = WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, pData);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, false);
            WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, pData);
            return status == 0;
        }
        catch { return false; }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (pCat != IntPtr.Zero) Marshal.FreeHGlobal(pCat);
            if (pCatPath != IntPtr.Zero) Marshal.FreeHGlobal(pCatPath);
            if (pMemberPath != IntPtr.Zero) Marshal.FreeHGlobal(pMemberPath);
            if (pTag != IntPtr.Zero) Marshal.FreeHGlobal(pTag);
        }
    }
}
