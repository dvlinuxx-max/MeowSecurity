using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using MeowSecurity.Core.Ipc;

namespace MeowSecurity.Gui;

/// <summary>
/// The application's side of the privilege boundary.
///
/// Three things need administrator rights: the kernel trace session, reading protected process
/// images, and changing a machine-wide auto-start entry. Rather than run the whole application
/// elevated — which a packaged app may not do, and which gives far more privilege than the job
/// needs — a small helper is started with the runas verb when one of those is first asked for.
/// The user sees one prompt, for one action, and the interface itself stays unprivileged.
///
/// If the user declines the prompt, nothing breaks: the monitor keeps running with the
/// visibility it already had, and says which parts are limited.
/// </summary>
public sealed class EngineClient : IDisposable
{
    private NamedPipeClientStream? _pipe;
    private Process? _helper;
    private CancellationTokenSource? _reading;

    /// <summary>A process the helper saw start. Raised on a background thread.</summary>
    public event Action<MeowSecurity.Core.Etw.ProcessStart>? ProcessStarted;

    public bool IsConnected => _pipe?.IsConnected == true;

    /// <summary>Why the last attempt failed, for the settings page to show.</summary>
    public string? Error { get; private set; }

    /// <summary>True when the user declined the prompt — worth saying differently from a fault.</summary>
    public bool Declined { get; private set; }

    /// <summary>
    /// Starts the helper if it is not already up, and connects. Returns false when the user
    /// declined elevation or the helper could not be reached.
    /// </summary>
    public async Task<bool> ConnectAsync(CancellationToken token = default)
    {
        if (IsConnected) return true;

        Declined = false;
        Error = null;

        string exe = Path.Combine(AppContext.BaseDirectory, "MeowSecurity.Engine.exe");
        if (!File.Exists(exe))
        {
            Error = "engine not found beside the application";
            return false;
        }

        try
        {
            _helper = Process.Start(new ProcessStartInfo(exe, "--serve")
            {
                UseShellExecute = true,   // required for the runas verb
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // 1223: the user said no. That is an answer, not a failure.
            Declined = true;
            return false;
        }

        var pipe = new NamedPipeClientStream(".", Frame.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            // The helper has to get through UAC and open its endpoint first.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await pipe.ConnectAsync(timeout.Token);
        }
        catch (Exception ex)
        {
            pipe.Dispose();
            Error = ex is OperationCanceledException ? "the engine did not start in time" : ex.Message;
            return false;
        }

        _pipe = pipe;
        _reading = CancellationTokenSource.CreateLinkedTokenSource(token);
        _ = Task.Run(() => ReadLoopAsync(_reading.Token), CancellationToken.None);

        var hello = await SendAsync(new Request { Command = Command.Ping }, token);
        if (hello?.Ok != true)
        {
            Error = hello?.Text ?? "the engine refused the connection";
            Dispose();
            return false;
        }

        return true;
    }

    /// <summary>
    /// One reader owns the pipe. Replies are handed to whoever is waiting; pushed events go to
    /// the event handler.
    ///
    /// This is not a nicety: a stream has no message boundaries of its own, so two tasks
    /// reading it concurrently take bytes out of each other's frames and the protocol
    /// desynchronises. That failure looks like malformed JSON and is maddening to chase, so
    /// there is exactly one reader by construction.
    /// </summary>
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Queue<TaskCompletionSource<Message>> _waiting = new();

    public async Task<Message?> SendAsync(Request request, CancellationToken token = default)
    {
        if (_pipe is null || !_pipe.IsConnected) return null;

        var pending = new TaskCompletionSource<Message>(TaskCreationOptions.RunContinuationsAsynchronously);
        await _writeLock.WaitAsync(token);
        try
        {
            lock (_waiting) _waiting.Enqueue(pending);
            await Frame.WriteAsync(_pipe, request, token);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            lock (_waiting) _waiting.Clear();
            Error = "lost contact with the engine";
            return null;
        }
        finally
        {
            _writeLock.Release();
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            return await pending.Task.WaitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Error = "the engine did not answer";
            return null;
        }
    }

    /// <summary>Sends without waiting for the reply, for the fire-and-forget verbs.</summary>
    public async Task<bool> TellAsync(Request request, CancellationToken token = default)
    {
        if (_pipe is null || !_pipe.IsConnected) return false;
        try
        {
            await Frame.WriteAsync(_pipe, request, token);
            return true;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads whatever the helper pushes. Only process-start events arrive this way; replies to
    /// commands are read by the caller that sent them.
    /// </summary>
    private async Task ReadLoopAsync(CancellationToken token)
    {
        try
        {
            while (_pipe is { IsConnected: true } && !token.IsCancellationRequested)
            {
                var message = await Frame.ReadAsync<Message>(_pipe, token);
                if (message is null) break;

                if (message.Type == "reply")
                {
                    TaskCompletionSource<Message>? waiting = null;
                    lock (_waiting) if (_waiting.Count > 0) waiting = _waiting.Dequeue();
                    waiting?.TrySetResult(message);
                    continue;
                }

                if (message.Type != "process-start") continue;

                ProcessStarted?.Invoke(new MeowSecurity.Core.Etw.ProcessStart(
                    message.TimeUtc, message.Pid, message.ParentPid,
                    message.Name ?? "", message.ImagePath, message.CommandLine, message.ParentName));
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException
                                      or InvalidDataException)
        {
            // The helper went away; the application carries on without it.
        }
        finally
        {
            lock (_waiting)
            {
                while (_waiting.Count > 0) _waiting.Dequeue().TrySetCanceled();
            }
        }
    }

    public void Dispose()
    {
        try { _reading?.Cancel(); } catch { }
        try { _pipe?.Dispose(); } catch { }
        _pipe = null;

        // The helper exits on its own when the pipe closes; this is only for the case where
        // it did not notice. Never leave an elevated process behind.
        try
        {
            if (_helper is { HasExited: false }) _helper.Kill();
        }
        catch { }
        _helper = null;
    }
}
