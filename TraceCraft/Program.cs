using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

const string USAGE =
@"TraceCraft single-file (collector + parser + sigma exporter)

Usage:
  TraceCraft collect <output.ndjson>
  TraceCraft gen-sigma <input.ndjson> <output.yml>
  TraceCraft help
";

if (args.Length == 0 || args[0] == "help")
{
    Console.WriteLine(USAGE);
    return 0;
}

var cmd = args[0].ToLowerInvariant();

try
{
    if (cmd == "collect")
    {
        if (args.Length < 2)
        {
            Console.WriteLine("collect requires an output file path.\n" + USAGE);
            return 1;
        }
        var outPath = args[1];
        await Collector.RunLiveCollectionAsync(outPath);
        return 0;
    }
    else if (cmd == "gen-sigma")
    {
        if (args.Length < 3)
        {
            Console.WriteLine("gen-sigma requires input ndjson and output yml paths.\n" + USAGE);
            return 1;
        }
        var inPath = args[1];
        var outPath = args[2];
        await SigmaGenerator.GenerateFromNdjsonAsync(inPath, outPath);
        return 0;
    }
    else
    {
        Console.WriteLine("Unknown command.\n" + USAGE);
        return 1;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Fatal: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
    return 2;
}

record TraceEventRecord
(
    DateTime Timestamp,
    string Provider,
    string EventName,
    string Hostname,
    string? ProcessName,
    int? Pid,
    int? ParentPid,
    string? CommandLine,
    string? Path,
    string? Details
);

static class JsonUtil
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };
}

static class Collector
{
    public static async Task RunLiveCollectionAsync(string outPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("ETW collection only runs on Windows.");

        if (!IsElevated())
        {
            Console.Error.WriteLine("Collector must be run elevated (admin). Exiting.");
            return;
        }

        Console.WriteLine($"Starting live collection -> {outPath}");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("Stopping... (flushing)\n");
            cts.Cancel();
        };

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath)) ?? ".");

        using var writer = new StreamWriter(new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.Read));

        var sessionName = "TraceCraftSession_" + Guid.NewGuid().ToString("N");
        using var session = new TraceEventSession(sessionName, null);

        Console.WriteLine("Enabling kernel providers: Process, ImageLoad, FileIO, NetworkTCPIP (best-effort)");
        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.ImageLoad |
            KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.NetworkTCPIP
        );

        session.EnableProvider("Microsoft-Windows-PowerShell", TraceEventLevel.Informational);
        session.EnableProvider("Microsoft-Windows-DotNETRuntime", TraceEventLevel.Informational);

        var source = session.Source;

        source.AllEvents += (evt) =>
        {
            try
            {
                var rec = MapTraceEventToRecord(evt);
                if (rec is not null)
                {
                    var json = JsonSerializer.Serialize(rec, JsonUtil.Options);
                    lock (writer)
                    {
                        writer.WriteLine(json);
                        writer.Flush();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Event map error: {ex.Message}");
            }
        };

        var t = Task.Run(() => source.Process(), cts.Token);

        Console.WriteLine("Collecting... press Ctrl+C to stop.");

        try
        {
            await t;
        }
        catch (OperationCanceledException) { }
        finally
        {
            session.Dispose();
            Console.WriteLine("Session disposed, collection finished.");
        }
    }

    static TraceEventRecord? MapTraceEventToRecord(TraceEvent evt)
    {
        if (string.IsNullOrEmpty(evt.ProviderName))
            return null;

        string provider = evt.ProviderName;
        string eName = evt.EventName ?? evt.ID.ToString();

        string? procName = null;
        int? pid = null;
        int? ppid = null;
        string? cmd = null;
        string? path = null;
        string? details = null;

        if (evt.ProviderName == "Microsoft-Windows-Kernel-Process")
        {
            try
            {
                pid = TryGetInt(evt, "ProcessID");
                ppid = TryGetInt(evt, "ParentID");
                procName = evt.PayloadByName("ImageFileName")?.ToString();
                cmd = evt.PayloadByName("CommandLine")?.ToString();
            }
            catch { }
        }
        else if (evt.ProviderName.Contains("Kernel-File") || evt.ProviderName == "Microsoft-Windows-Kernel-File")
        {
            path = evt.PayloadByName("FileName")?.ToString();
        }
        else if (evt.ProviderName.Contains("PowerShell"))
        {
            procName = "powershell.exe";
            cmd = evt.PayloadByName("CommandLine")?.ToString() ?? evt.PayloadByName("ScriptBlockText")?.ToString();
            pid = TryGetInt(evt, "ProcessId");
        }
        else if (evt.ProviderName.Contains("DotNETRuntime") || evt.ProviderName.Contains("CLR"))
        {
            procName = evt.PayloadByName("Module")?.ToString() ?? evt.ProcessName;
            pid = TryGetInt(evt, "ProcessId") ?? TryGetInt(evt, "PID");
        }

        if (pid == null)
        {
            pid = evt.ProcessID > 0 ? evt.ProcessID : null;
        }
        if (procName == null)
            procName = evt.ProcessName;

        try
        {
            var kv = new Dictionary<string, object?>();
            foreach (var name in evt.PayloadNames)
            {
                if (string.IsNullOrEmpty(name)) continue;
                kv[name] = evt.PayloadByName(name);
            }
            if (kv.Count > 0)
                details = JsonSerializer.Serialize(kv, JsonUtil.Options);
        }
        catch { }

        var rec = new TraceEventRecord(
            Timestamp: evt.TimeStamp,
            Provider: provider,
            EventName: eName,
            Hostname: Environment.MachineName,
            ProcessName: procName,
            Pid: pid,
            ParentPid: ppid,
            CommandLine: cmd,
            Path: path,
            Details: details
        );

        return rec;
    }

    static int? TryGetInt(TraceEvent evt, string name)
    {
        try
        {
            var val = evt.PayloadByName(name);
            if (val == null) return null;
            return Convert.ToInt32(val);
        }
        catch { return null; }
    }

    static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}

static class SigmaGenerator
{
    public static async Task GenerateFromNdjsonAsync(string ndjsonPath, string outSigmaPath)
    {
        if (!File.Exists(ndjsonPath))
            throw new FileNotFoundException("NDJSON input not found.", ndjsonPath);

        Console.WriteLine($"Loading events from {ndjsonPath}...");
        var events = new List<TraceEventRecord>();

        using var sr = new StreamReader(ndjsonPath);
        string? line;
        while ((line = await sr.ReadLineAsync()) != null)
        {
            try
            {
                var rec = JsonSerializer.Deserialize<TraceEventRecord>(line, JsonUtil.Options);
                if (rec != null)
                    events.Add(rec);
            }
            catch { }
        }

        Console.WriteLine($"Loaded {events.Count} records. Running conservative heuristic analysis...");

        var suspiciousKeywords = new[] { "powershell", "rundll32", "regsvr32", "wscript", "cscript", "mshta" };

        var candidates = events
            .Where(e => !string.IsNullOrEmpty(e.CommandLine) && suspiciousKeywords.Any(k => e.CommandLine!.Contains(k, StringComparison.OrdinalIgnoreCase)))
            .GroupBy(e => new { e.ProcessName, e.Pid })
            .Select(g => (dynamic)new
            {
                Process = g.Key.ProcessName ?? "<unknown>",
                Pid = g.Key.Pid,
                Count = g.Count(),
                SampleCmd = g.Select(x => x.CommandLine).FirstOrDefault(x => !string.IsNullOrEmpty(x)) ?? "",
                RelatedRegistryWrites = events.Count(ev => ev.Provider?.Contains("Registry", StringComparison.OrdinalIgnoreCase) == true && ev.Pid == g.Key.Pid)
            })
            .ToList();

        var sigma = BuildConservativeSigma(candidates, events);

        await File.WriteAllTextAsync(outSigmaPath, sigma);
        Console.WriteLine($"Sigma rule saved to {outSigmaPath}");
    }

    static string BuildConservativeSigma(List<dynamic> candidates, List<TraceEventRecord> allEvents)
    {
        var id = Guid.NewGuid().ToString();
        var title = "TraceCraft - suspicious process commandline heuristics";

        var top = candidates.Take(5).ToList();

        var selectors = new List<string>();
        foreach (var c in top)
        {
            var sample = c.SampleCmd?.Replace("\n", " ").Replace("\r", " ") ?? "";
            if (string.IsNullOrWhiteSpace(sample)) continue;
            var tokens = sample.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                               .Take(6)
                               .Select((Func<string, string>)(tok => tok.Replace("\"", "'")))
                               .ToList();
            if (tokens.Count > 0)
            {
                selectors.Add(string.Join(" ", tokens));
            }
        }

        if (selectors.Count == 0)
        {
            selectors.Add("powershell -enc");
        }

        using var sw = new StringWriter();
        sw.WriteLine("title: " + title);
        sw.WriteLine("id: " + id);
        sw.WriteLine("status: experimental");
        sw.WriteLine("description: Generated by TraceCraft (conservative). Review before use.");
        sw.WriteLine("logsource:");
        sw.WriteLine("  product: windows");
        sw.WriteLine("detection:");
        sw.WriteLine("  selection:");
        sw.WriteLine("    CommandLine|contains:");
        foreach (var s in selectors)
        {
            sw.WriteLine($"      - '{EscapeYaml(s)}'");
        }
        sw.WriteLine("  condition: selection");
        sw.WriteLine("level: low");
        sw.WriteLine("tags:");
        sw.WriteLine("  - attack.execution");
        sw.WriteLine("author: TraceCraft (ethical research)\n");

        sw.Flush();
        return sw.ToString();
    }

    static string EscapeYaml(string s) => s.Replace("'", "''");
}
