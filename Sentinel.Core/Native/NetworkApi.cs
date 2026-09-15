using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>
/// IP Helper tables that attribute every TCP/UDP endpoint to the process that owns it,
/// via GetExtendedTcpTable / GetExtendedUdpTable with the OWNER_PID table class.
/// </summary>
internal static class NetworkApi
{
    public const int AF_INET = 2;
    public const int AF_INET6 = 23;

    // TCP_TABLE_OWNER_PID_ALL / UDP_TABLE_OWNER_PID
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;   // network byte order, only low 16 bits used
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    public static readonly string[] TcpStateName =
    [
        "", "CLOSED", "LISTEN", "SYN-SENT", "SYN-RCVD", "ESTABLISHED",
        "FIN-WAIT1", "FIN-WAIT2", "CLOSE-WAIT", "CLOSING", "LAST-ACK",
        "TIME-WAIT", "DELETE-TCB",
    ];
}
