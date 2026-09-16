using System.Net;
using System.Runtime.InteropServices;
using MeowSecurity.Core.Native;

namespace MeowSecurity.Core.Network;

/// <summary>
/// Snapshots every IPv4 TCP and UDP endpoint with the PID that owns it, so the process
/// view can show exactly who is talking to the network and where.
/// </summary>
public sealed class NetworkScanner
{
    public IReadOnlyList<Connection> Scan()
    {
        var list = new List<Connection>();
        ReadTcp(list);
        ReadUdp(list);
        return list;
    }

    private static void ReadTcp(List<Connection> list)
    {
        int size = 0;
        NetworkApi.GetExtendedTcpTable(IntPtr.Zero, ref size, true,
            NetworkApi.AF_INET, NetworkApi.TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (NetworkApi.GetExtendedTcpTable(table, ref size, true,
                    NetworkApi.AF_INET, NetworkApi.TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return;

            int count = Marshal.ReadInt32(table);
            IntPtr row = table + 4;
            int rowSize = Marshal.SizeOf<NetworkApi.MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var r = Marshal.PtrToStructure<NetworkApi.MIB_TCPROW_OWNER_PID>(row);
                uint stateIdx = r.state;
                list.Add(new Connection
                {
                    Transport = Transport.Tcp,
                    Pid = (int)r.owningPid,
                    Local = new IPEndPoint(r.localAddr, Port(r.localPort)),
                    Remote = new IPEndPoint(r.remoteAddr, Port(r.remotePort)),
                    State = stateIdx < NetworkApi.TcpStateName.Length
                        ? NetworkApi.TcpStateName[stateIdx] : stateIdx.ToString(),
                });
                row += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static void ReadUdp(List<Connection> list)
    {
        int size = 0;
        NetworkApi.GetExtendedUdpTable(IntPtr.Zero, ref size, true,
            NetworkApi.AF_INET, NetworkApi.UDP_TABLE_OWNER_PID, 0);
        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (NetworkApi.GetExtendedUdpTable(table, ref size, true,
                    NetworkApi.AF_INET, NetworkApi.UDP_TABLE_OWNER_PID, 0) != 0)
                return;

            int count = Marshal.ReadInt32(table);
            IntPtr row = table + 4;
            int rowSize = Marshal.SizeOf<NetworkApi.MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var r = Marshal.PtrToStructure<NetworkApi.MIB_UDPROW_OWNER_PID>(row);
                list.Add(new Connection
                {
                    Transport = Transport.Udp,
                    Pid = (int)r.owningPid,
                    Local = new IPEndPoint(r.localAddr, Port(r.localPort)),
                    Remote = null,
                    State = "",
                });
                row += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    // The port fields are big-endian in the low 16 bits.
    private static int Port(uint netPort)
    {
        int lo = (int)(netPort & 0xFF);
        int hi = (int)((netPort >> 8) & 0xFF);
        return (lo << 8) | hi;
    }
}
