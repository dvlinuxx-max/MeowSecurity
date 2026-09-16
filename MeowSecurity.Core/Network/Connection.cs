using System.Net;

namespace MeowSecurity.Core.Network;

public enum Transport { Tcp, Udp }

public sealed class Connection
{
    public required Transport Transport { get; init; }
    public required int Pid { get; init; }
    public required IPEndPoint Local { get; init; }
    public IPEndPoint? Remote { get; init; }   // null for UDP / listeners
    public string State { get; init; } = "";

    public bool IsListener => State is "LISTEN" || Remote is null || Remote.Address.Equals(IPAddress.Any);

    public override string ToString()
    {
        string arrow = Remote is null ? "" : $" -> {Remote}";
        string st = string.IsNullOrEmpty(State) ? "" : $" [{State}]";
        return $"{Transport} {Local}{arrow}{st}";
    }
}
