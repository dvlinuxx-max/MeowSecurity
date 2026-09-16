using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using MeowSecurity.Core.Etw;
using MeowSecurity.Core.Ipc;
using MeowSecurity.Core.Native;
using MeowSecurity.Core.Persistence;

namespace MeowSecurity.Engine;

/// <summary>
/// The only part of Meow Security that runs elevated.
///
/// Everything the application does at standard privileges stays in the application. This
/// process exists for the three things Windows will not allow at medium integrity — opening a
/// kernel trace session, reading protected process images, and changing a machine-wide
/// auto-start entry — and it is deliberately built to be incapable of anything else.
///
/// It accepts four verbs over one pipe, executes no path it is given, exits when the
/// application that started it goes away, and refuses any client that is not that application.
/// A privilege boundary is only as good as what it refuses, so the refusals are the design.
/// </summary>
internal static class Program
{
    private static ProcessStartWatcher? _watcher;
    private static readonly CancellationTokenSource Life = new();

    private static async Task<int> Main(string[] args)
    {
        // Started by hand, this tells whoever ran it what it is and refuses to sit idle.
        if (!args.Contains("--serve"))
        {
            Console.WriteLine("Meow Security engine — the elevated helper for the application.");
            Console.WriteLine("It is started by Meow Security when needed and is not meant to be run directly.");
            return 1;
        }

        using var server = CreateServer();
        try
        {
            // If nobody connects, this process must not sit here elevated forever. That is
            // exactly what happens when the application crashes between starting the helper
            // and reaching it, and an abandoned elevated endpoint is the thing this design
            // exists to avoid.
            using var patience = CancellationTokenSource.CreateLinkedTokenSource(Life.Token);
            patience.CancelAfter(TimeSpan.FromSeconds(45));
            await server.WaitForConnectionAsync(patience.Token);
        }
        catch (OperationCanceledException)
        {
            Log("no client connected; exiting rather than lingering elevated");
            return 0;
        }

        if (!CallerIsOurApplication(server, out string why))
        {
            // A refused connection to an elevated endpoint is worth recording: it is either a
            // fault in our own layout or something on the machine trying the door.
            Log($"refused a client: {why}");
            await Frame.WriteAsync(server, Message.Reply(false, "caller is not Meow Security"));
            await server.FlushAsync();
            server.WaitForPipeDrain();
            return 2;
        }

        await ServeAsync(server);
        _watcher?.Dispose();
        return 0;
    }

    /// <summary>
    /// The pipe is readable and writable by this user alone.
    ///
    /// An elevated endpoint that anyone on the machine may open is a way in, not a feature, so
    /// the descriptor names the interactive user and nobody else — not Everyone, not Users.
    /// </summary>
    private static NamedPipeServerStream CreateServer()
    {
        var rules = new PipeSecurity();
        var me = WindowsIdentity.GetCurrent().User!;
        rules.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        rules.SetOwner(me);

        return NamedPipeServerStreamAcl.Create(
            Frame.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: Frame.MaxBytes,
            outBufferSize: Frame.MaxBytes,
            rules);
    }

    /// <summary>
    /// Confirms the client is the application that ships beside this helper.
    ///
    /// Same user is not enough on its own: any program running as the user could otherwise
    /// drive an elevated endpoint. The client's own image has to be the expected one, sitting
    /// in this same directory.
    /// </summary>
    private static bool CallerIsOurApplication(NamedPipeServerStream server, out string why)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out uint pid))
            {
                why = $"could not read the client's process id (win32 {Marshal.GetLastWin32Error()})";
                return false;
            }

            string? clientPath = ProcessDetails.GetImagePath((int)pid);
            if (clientPath is null)
            {
                why = $"could not read the image path of client pid {pid}";
                return false;
            }

            string expected = Path.Combine(AppContext.BaseDirectory, "MeowSecurity.exe");
            bool same = string.Equals(Path.GetFullPath(clientPath), Path.GetFullPath(expected),
                StringComparison.OrdinalIgnoreCase);
            why = same ? "" : $"client is {clientPath}, expected {expected}";
            return same;
        }
        catch (Exception ex)
        {
            why = ex.Message;
            return false;
        }
    }

    /// <summary>A short log beside the application's own, for the few things worth explaining.</summary>
    private static void Log(string line)
    {
        try
        {
            string path = Path.Combine(MeowSecurity.Core.Intel.IntelSettings.ConfigDirectory, "engine.log");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {line}{Environment.NewLine}");
        }
        catch { /* logging must never be the reason anything fails */ }
    }

    private static async Task ServeAsync(NamedPipeServerStream pipe)
    {
        while (pipe.IsConnected && !Life.IsCancellationRequested)
        {
            Request? request;
            try
            {
                request = await Frame.ReadAsync<Request>(pipe, Life.Token);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or OperationCanceledException)
            {
                // A malformed frame or a vanished client both mean the same thing: stop.
                break;
            }

            if (request is null) break;   // the application closed — our reason to exist went with it

            var reply = await HandleAsync(request, pipe);
            try { await Frame.WriteAsync(pipe, reply, Life.Token); }
            catch (IOException) { break; }
        }
    }

    private static async Task<Message> HandleAsync(Request request, NamedPipeServerStream pipe)
    {
        switch (request.Command)
        {
            case Command.Ping:
                return Message.Reply(true, "ready");

            case Command.StartCapture:
                return StartCapture(pipe);

            case Command.StopCapture:
                _watcher?.Dispose();
                _watcher = null;
                return Message.Reply(true, "stopped");

            case Command.SetAutorun:
                return SetAutorun(request);

            case Command.Shutdown:
                await Life.CancelAsync();
                return Message.Reply(true, "closing");

            default:
                return Message.Reply(false, "unknown command");
        }
    }

    private static Message StartCapture(NamedPipeServerStream pipe)
    {
        if (_watcher is not null) return Message.Reply(true, "already running");

        _watcher = new ProcessStartWatcher();
        _watcher.Started += p =>
        {
            // Fire and forget: a slow or dead client must never stall the ETW callback.
            _ = Frame.WriteAsync(pipe, new Message
            {
                Type = "process-start",
                Pid = p.Pid,
                ParentPid = p.ParentPid,
                Name = p.Name,
                ParentName = p.ParentName,
                ImagePath = p.ImagePath,
                CommandLine = p.CommandLine,
                TimeUtc = p.TimeUtc,
            }, Life.Token).ContinueWith(_ => { }, TaskScheduler.Default);
        };

        return _watcher.Start()
            ? Message.Reply(true, "capturing")
            : Message.Reply(false, _watcher.Error, elevate: _watcher.State == EtwState.NeedsElevation);
    }

    /// <summary>
    /// Toggles one entry the application already found. It re-scans and matches by identity
    /// rather than acting on anything the client sends: the client names an entry, it does not
    /// describe one, so there is no path or registry key here to be talked into writing.
    /// </summary>
    private static Message SetAutorun(Request request)
    {
        if (string.IsNullOrWhiteSpace(request.EntryId))
            return Message.Reply(false, "no entry named");

        var match = new AutorunScanner().Scan()
            .FirstOrDefault(e => AutorunControl.IdentityOf(e) == request.EntryId);
        if (match is null) return Message.Reply(false, "entry not found");

        var result = AutorunControl.SetEnabled(match, request.Enable);
        return Message.Reply(result.Ok, result.Message, result.NeedsElevation);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);
}
