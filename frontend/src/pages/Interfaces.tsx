import { useState, useMemo, useRef, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchInterfaceList,
  enableInterface,
  disableInterface,
  setProbeMode,
  runProbes,
  fetchProbeStatus,
  fetchRemoteSensors,
  disconnectRemoteSensor,
  fetchBuildTargets,
  checkSensorName,
  type NetworkInterface,
  type ProbeInfo,
  type RemoteSensor,
  type BuildTarget,
  type BuildRequestBody,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import {
  WifiOff,
  Cable,
  Wifi,
  Container,
  Network,
  Globe,
  Monitor,
  Radio,
  Hammer,
  Download,
  Loader2,
} from "lucide-react";

// --- Category classification ---

interface CategoryInfo {
  label: string;
  icon: React.ElementType;
  description: string;
  color: string;
}

const CATEGORIES: Record<string, CategoryInfo> = {
  ethernet: {
    label: "Physical / Ethernet",
    icon: Cable,
    description: "Wired ethernet interfaces",
    color: "text-blue-400",
  },
  wireless: {
    label: "Wireless",
    icon: Wifi,
    description: "Wi-Fi and wireless interfaces",
    color: "text-green-400",
  },
  bridge: {
    label: "Bridge",
    icon: Network,
    description: "Bridged network interfaces",
    color: "text-purple-400",
  },
  virtual: {
    label: "Containers & Virtualization",
    icon: Container,
    description: "Docker, Kubernetes, KVM, and virtual machine interfaces",
    color: "text-orange-400",
  },
  tunnel: {
    label: "VPN / Tunnel",
    icon: Globe,
    description: "VPN tunnels, WireGuard, TAP/TUN interfaces",
    color: "text-cyan-400",
  },
  unknown: {
    label: "Other",
    icon: Monitor,
    description: "Unclassified interfaces",
    color: "text-muted-foreground",
  },
};

function classifyCategory(iface: NetworkInterface): string {
  const name = iface.name.toLowerCase();
  const type = (iface.type ?? "").toLowerCase();

  // Wireless
  if (type === "wireless" || name.startsWith("wl") || name.startsWith("wlan")) return "wireless";

  // Container / Virtualization
  if (
    name.startsWith("docker") || name.startsWith("veth") || name.startsWith("cali") ||
    name.startsWith("flannel") || name.startsWith("cni") || name.startsWith("lxc") ||
    name.startsWith("virbr") || name.startsWith("vmnet") || name.startsWith("vboxnet") ||
    type === "virtual"
  ) return "virtual";

  // Bridge
  if (name.startsWith("br") || type === "bridge") return "bridge";

  // Tunnel / VPN
  if (
    name.startsWith("tun") || name.startsWith("tap") || name.startsWith("wg") ||
    name.startsWith("tailscale") || name.startsWith("nordlynx") ||
    type === "tunnel"
  ) return "tunnel";

  // Ethernet (default for physical)
  if (type === "ethernet" || name.startsWith("eth") || name.startsWith("en") || name.startsWith("em")) return "ethernet";

  return "unknown";
}

// --- Main ---

export default function Interfaces() {
  const queryClient = useQueryClient();
  const [probeDialogIface, setProbeDialogIface] = useState<string | null>(null);
  const [probeList, setProbeList] = useState<ProbeInfo[]>([]);
  const [selectedProbes, setSelectedProbes] = useState<Set<string>>(new Set());
  const [probeLoading, setProbeLoading] = useState(false);

  const { data } = useQuery({
    queryKey: ["interfaces"],
    queryFn: fetchInterfaceList,
    refetchInterval: 15000,
    staleTime: 10000,
  });

  const { data: sensors = [] } = useQuery({
    queryKey: ["remote-sensors"],
    queryFn: fetchRemoteSensors,
    refetchInterval: 5000,
  });

  const { data: buildTargets = [] } = useQuery({
    queryKey: ["build-targets"],
    queryFn: fetchBuildTargets,
  });

  // Build sensor state
  const [buildDialogOpen, setBuildDialogOpen] = useState(false);
  const [buildName, setBuildName] = useState("");
  const [buildServer, setBuildServer] = useState(
    typeof window !== "undefined" ? `${window.location.hostname}:8443` : "127.0.0.1:8443"
  );
  const [buildInterface, setBuildInterface] = useState("eth0");
  const [buildTarget, setBuildTarget] = useState("linux-x86_64");
  const [buildBufferMb, setBuildBufferMb] = useState(100);
  const [buildInProgress, setBuildInProgress] = useState(false);
  const [buildLog, setBuildLog] = useState<Array<{ stage: string; message: string }>>([]);
  const [buildDownloadId, setBuildDownloadId] = useState<string | null>(null);
  const [buildDownloadFilename, setBuildDownloadFilename] = useState("leetha-sensor");
  const buildLogRef = useRef<HTMLDivElement>(null);

  // Auto-scroll build log
  useEffect(() => {
    if (buildLogRef.current) {
      buildLogRef.current.scrollTop = buildLogRef.current.scrollHeight;
    }
  }, [buildLog]);

  // Update buffer size when target changes
  const handleTargetChange = (targetId: string) => {
    setBuildTarget(targetId);
    const target = buildTargets.find((t) => t.id === targetId);
    if (target) setBuildBufferMb(target.default_buffer_mb);
  };

  const handleBuildSensor = async () => {
    if (!buildName.trim()) {
      toast.error("Sensor name is required");
      return;
    }

    // Check for duplicate name
    try {
      const nameCheck = await checkSensorName(buildName);
      if (nameCheck.exists) {
        if (!confirm(`A certificate for '${buildName}' already exists. Building will revoke the old certificate and issue a new one. Continue?`)) {
          return;
        }
      }
    } catch {
      // Ignore check failures, proceed with build
    }

    setBuildInProgress(true);
    setBuildLog([]);
    setBuildDownloadId(null);

    const body: BuildRequestBody = {
      name: buildName,
      server: buildServer,
      interface: buildInterface,
      target: buildTarget,
      buffer_size_mb: buildBufferMb,
    };

    try {
      const token = localStorage.getItem("leetha_token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const resp = await fetch("/api/remote/build", {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        toast.error(err.detail || "Build request failed");
        setBuildInProgress(false);
        return;
      }

      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      if (!reader) {
        toast.error("Failed to read build stream");
        setBuildInProgress(false);
        return;
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const dataMatch = line.match(/^data:\s*(.+)$/m);
          if (!dataMatch) continue;
          try {
            const event = JSON.parse(dataMatch[1]);
            setBuildLog((prev) => [...prev, event]);

            if (event.stage === "done") {
              const doneData = JSON.parse(event.message);
              setBuildDownloadId(doneData.download_id);
              setBuildDownloadFilename(doneData.filename || "leetha-sensor");
              toast.success("Sensor build complete");
            } else if (event.stage === "error") {
              toast.error("Build failed");
            }
          } catch {
            // Skip unparseable lines
          }
        }
      }
    } catch (err) {
      toast.error(`Build error: ${err}`);
    } finally {
      setBuildInProgress(false);
    }
  };

  const interfaces = data?.detected ?? [];

  // Group by category
  const grouped = useMemo(() => {
    const groups: Record<string, NetworkInterface[]> = {};
    for (const iface of interfaces) {
      const cat = classifyCategory(iface);
      if (!groups[cat]) groups[cat] = [];
      groups[cat]!.push(iface);
    }
    // Sort categories in display order
    const order = ["ethernet", "wireless", "tunnel", "bridge", "virtual", "unknown"];
    const sorted: Array<[string, NetworkInterface[]]> = [];
    for (const key of order) {
      if (groups[key] && groups[key].length > 0) sorted.push([key, groups[key]]);
    }
    return sorted;
  }, [interfaces]);

  const capturingCount = interfaces.filter((i) => i.capturing).length;

  const handleCaptureToggle = async (iface: NetworkInterface) => {
    const isCapturing = !!iface.capturing;
    try {
      if (isCapturing) {
        await disableInterface(iface.name);
        toast.success(`Stopped capture on ${iface.name}`);
      } else {
        await enableInterface(iface.name);
        toast.success(`Started capture on ${iface.name}`);
      }
      queryClient.invalidateQueries({ queryKey: ["interfaces"] });
    } catch (err) {
      toast.error(`Failed: ${err}`);
    }
  };

  const handleDisconnectSensor = async (name: string) => {
    try {
      await disconnectRemoteSensor(name);
      toast.success(`Disconnected sensor ${name}`);
      queryClient.invalidateQueries({ queryKey: ["remote-sensors"] });
    } catch (err) {
      toast.error(`Failed to disconnect: ${err}`);
    }
  };

  const handleProbeModeChange = async (name: string, mode: string) => {
    try {
      await setProbeMode(name, mode);
      toast.success(`Set ${name} to ${mode}`);
      queryClient.invalidateQueries({ queryKey: ["interfaces"] });
    } catch (err) {
      toast.error(`Failed: ${err}`);
    }
  };

  const openProbeDialog = async (name: string) => {
    setProbeDialogIface(name);
    setSelectedProbes(new Set());
    try {
      const result = await fetchProbeStatus(name);
      setProbeList(result.available_probes ?? result.probes ?? []);
    } catch {
      setProbeList([]);
    }
  };

  const toggleProbe = (probeName: string) => {
    setSelectedProbes((prev) => {
      const next = new Set(prev);
      if (next.has(probeName)) next.delete(probeName);
      else next.add(probeName);
      return next;
    });
  };

  const handleRunProbes = async (all: boolean) => {
    if (!probeDialogIface) return;
    setProbeLoading(true);
    try {
      const probes = all ? "all" : Array.from(selectedProbes);
      await runProbes(probeDialogIface, probes);
      toast.success(all ? `Running all probes on ${probeDialogIface}` : `Running ${selectedProbes.size} probe(s) on ${probeDialogIface}`);
      setProbeDialogIface(null);
    } catch (err) {
      toast.error(`Probe failed: ${err}`);
    } finally {
      setProbeLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <p className="text-sm text-muted-foreground max-w-xl">
          Select which network interfaces to capture on. Changes take effect immediately.
        </p>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span>{interfaces.length} detected</span>
          <span>&middot;</span>
          <span className={capturingCount > 0 ? "text-success" : ""}>{capturingCount} capturing</span>
        </div>
      </div>

      {/* Remote Sensors */}
      <div className="rounded-xl bg-card border border-border overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-3 border-b border-border">
          <Radio size={16} className="text-violet-400" />
          <div>
            <h3 className="text-sm font-semibold">Remote Sensors</h3>
            <p className="text-[11px] text-muted-foreground">Persistent packet capture agents streaming over WebSocket</p>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-muted-foreground">{sensors.length} connected</span>
            <Button
              variant="outline"
              size="sm"
              className="text-xs h-7 gap-1.5"
              onClick={() => setBuildDialogOpen(true)}
            >
              <Hammer size={12} />
              Build Sensor
            </Button>
          </div>
        </div>
        {sensors.length === 0 ? (
          <div className="px-5 py-6 text-center text-muted-foreground text-sm">
            No remote sensors connected. Use <code className="text-xs bg-secondary px-1.5 py-0.5 rounded">leetha remote ca issue</code> to set up a sensor.
          </div>
        ) : (
          <div className="divide-y divide-border">
            {sensors.map((sensor) => (
              <div key={sensor.name} className="flex items-center justify-between px-5 py-4 gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="h-2 w-2 rounded-full bg-success shrink-0" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{sensor.name}</span>
                      <Badge variant="outline" className="text-[10px] uppercase font-semibold text-violet-400 border-violet-400/30">
                        REMOTE
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {sensor.remote_ip} &middot; {Math.floor(sensor.uptime / 60)}m uptime
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-muted-foreground shrink-0">
                  <span>{sensor.packets.toLocaleString()} pkts</span>
                  <span>{(sensor.bytes / 1024 / 1024).toFixed(1)} MB</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs h-7 text-destructive hover:text-destructive"
                    onClick={() => handleDisconnectSensor(sensor.name)}
                  >
                    Disconnect
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {interfaces.length === 0 ? (
        <div className="rounded-xl bg-card border border-border flex flex-col items-center justify-center py-16 text-muted-foreground">
          <WifiOff size={32} className="mb-2" />
          <p className="font-medium">No interfaces detected</p>
          <p className="text-xs">Ensure the system has network interfaces available.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {grouped.map(([category, ifaces]) => {
            const catInfo = CATEGORIES[category] ?? CATEGORIES["unknown"]!;
            const CatIcon = catInfo!.icon;

            return (
              <div key={category} className="rounded-xl bg-card border border-border overflow-hidden">
                {/* Category header */}
                <div className="flex items-center gap-3 px-5 py-3 border-b border-border">
                  <CatIcon size={16} className={catInfo.color} />
                  <div>
                    <h3 className="text-sm font-semibold">{catInfo.label}</h3>
                    <p className="text-[11px] text-muted-foreground">{catInfo.description}</p>
                  </div>
                  <span className="ml-auto text-xs text-muted-foreground">{ifaces.length}</span>
                </div>

                {/* Interface rows */}
                <div className="divide-y divide-border">
                  {ifaces.map((iface) => {
                    const isActive = !!iface.capturing;
                    const isUp = iface.state?.toUpperCase() === "UP";

                    const ipv4 = (iface.bindings ?? []).filter((b) => !b.address.includes(":"));
                    const ipv6 = (iface.bindings ?? []).filter((b) => b.address.includes(":"));

                    return (
                      <div
                        key={iface.name}
                        className={cn(
                          "flex items-start justify-between px-5 py-4 gap-4",
                          isActive && "bg-primary/[0.03]"
                        )}
                      >
                        {/* Left: detailed info */}
                        <div className="space-y-2 min-w-0 flex-1">
                          {/* Name + badges */}
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-semibold text-sm">{iface.name}</span>
                            <Badge
                              variant="outline"
                              className="text-[10px] uppercase font-semibold text-muted-foreground"
                            >
                              {iface.type}
                            </Badge>
                            <Badge
                              variant={isUp ? "default" : "secondary"}
                              className={cn(
                                "text-[10px] uppercase font-semibold",
                                isUp ? "bg-success/20 text-success border-success/30" : "text-muted-foreground"
                              )}
                            >
                              {isUp ? "UP" : "DOWN"}
                            </Badge>
                            {isActive && (
                              <Badge className="text-[10px] uppercase font-semibold bg-primary/20 text-primary border-primary/30">
                                CAPTURING
                              </Badge>
                            )}
                          </div>

                          {/* Detail grid */}
                          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
                            {iface.mac && (
                              <>
                                <span className="text-muted-foreground">Hardware Address:</span>
                                <span className="font-data">{iface.mac}</span>
                              </>
                            )}
                            {ipv4.length > 0 && (
                              <>
                                <span className="text-muted-foreground">IPv4:</span>
                                <span className="font-data">
                                  {ipv4.map((b) => b.address + (b.prefix !== undefined ? `/${b.prefix}` : "")).join(", ")}
                                </span>
                              </>
                            )}
                            {ipv6.length > 0 && (
                              <>
                                <span className="text-muted-foreground">IPv6:</span>
                                <span className="font-data text-[11px] break-all">
                                  {ipv6.map((b) => b.address + (b.prefix !== undefined ? `/${b.prefix}` : "")).join(", ")}
                                </span>
                              </>
                            )}
                            {iface.mtu && (
                              <>
                                <span className="text-muted-foreground">MTU:</span>
                                <span>{iface.mtu}</span>
                              </>
                            )}
                            <span className="text-muted-foreground">Type:</span>
                            <span className="capitalize">{iface.type ?? "unknown"}</span>
                          </div>
                        </div>

                        {/* Right: controls */}
                        <div className="flex items-center gap-3 shrink-0 pt-1">
                          {isActive && (
                            <>
                              <Select
                                defaultValue="passive"
                                onValueChange={(val) => handleProbeModeChange(iface.name, val)}
                              >
                                <SelectTrigger className="h-7 w-[110px] text-xs">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="passive">Passive</SelectItem>
                                  <SelectItem value="probe-enabled">Probe</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-xs h-7"
                                onClick={() => openProbeDialog(iface.name)}
                              >
                                Probe
                              </Button>
                            </>
                          )}
                          <Switch
                            checked={isActive}
                            disabled={!isUp}
                            onCheckedChange={() => handleCaptureToggle(iface)}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Probe Dialog */}
      <Dialog
        open={probeDialogIface !== null}
        onOpenChange={(open) => { if (!open) setProbeDialogIface(null); }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Probe {probeDialogIface}</DialogTitle>
            <DialogDescription>Select probes to run or run all available probes.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2 max-h-64 overflow-y-auto py-2">
            {probeList.length === 0 ? (
              <p className="text-sm text-muted-foreground">No probes available.</p>
            ) : (
              probeList.map((probe) => (
                <label key={probe.name} className="flex items-start gap-3 p-2 rounded-lg hover:bg-secondary/50 cursor-pointer">
                  <input type="checkbox" checked={selectedProbes.has(probe.name)} onChange={() => toggleProbe(probe.name)} className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium">{probe.name}</div>
                    <div className="text-xs text-muted-foreground">{probe.description}</div>
                    {probe.requires_l2 && <Badge variant="outline" className="mt-1 text-[10px]">Requires L2</Badge>}
                  </div>
                </label>
              ))
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setProbeDialogIface(null)}>Close</Button>
            <Button variant="outline" onClick={() => handleRunProbes(false)} disabled={probeLoading || selectedProbes.size === 0}>Run Selected</Button>
            <Button onClick={() => handleRunProbes(true)} disabled={probeLoading || probeList.length === 0}>Run All</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Build Sensor Dialog */}
      <Dialog open={buildDialogOpen} onOpenChange={(open) => { if (!open && !buildInProgress) setBuildDialogOpen(false); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Build Sensor Binary</DialogTitle>
            <DialogDescription>
              Configure and compile a self-contained sensor with embedded certificates.
            </DialogDescription>
          </DialogHeader>

          {buildLog.length === 0 ? (
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="build-name">Sensor Name</Label>
                <Input
                  id="build-name"
                  placeholder="pi-sensor"
                  value={buildName}
                  onChange={(e) => setBuildName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="build-server">Server Address (IP:PORT)</Label>
                <Input
                  id="build-server"
                  placeholder="10.0.0.5:8443"
                  value={buildServer}
                  onChange={(e) => setBuildServer(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="build-iface">Capture Interface</Label>
                <Input
                  id="build-iface"
                  placeholder="eth0"
                  value={buildInterface}
                  onChange={(e) => setBuildInterface(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Target Platform</Label>
                <Select value={buildTarget} onValueChange={handleTargetChange}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {buildTargets.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="build-buffer">Ring Buffer Size (MB)</Label>
                <Input
                  id="build-buffer"
                  type="number"
                  min={1}
                  value={buildBufferMb}
                  onChange={(e) => setBuildBufferMb(parseInt(e.target.value) || 10)}
                />
              </div>
            </div>
          ) : (
            <div className="space-y-3 py-2">
              <div
                ref={buildLogRef}
                className="h-64 overflow-y-auto rounded-lg bg-black/50 p-3 font-mono text-xs space-y-0.5"
              >
                {buildLog.map((entry, i) => (
                  <div
                    key={i}
                    className={cn(
                      entry.stage === "error" && "text-destructive",
                      entry.stage === "done" && "text-success",
                      entry.stage === "compile" && "text-muted-foreground",
                      entry.stage === "certs" && "text-violet-400",
                      entry.stage === "config" && "text-cyan-400",
                    )}
                  >
                    <span className="text-muted-foreground/50">[{entry.stage}]</span>{" "}
                    {entry.stage === "done" ? "Build complete" : entry.message}
                  </div>
                ))}
                {buildInProgress && (
                  <div className="flex items-center gap-2 text-muted-foreground pt-1">
                    <Loader2 size={12} className="animate-spin" />
                    Building...
                  </div>
                )}
              </div>
            </div>
          )}

          <DialogFooter>
            {buildLog.length === 0 ? (
              <>
                <Button variant="outline" onClick={() => setBuildDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleBuildSensor} disabled={buildInProgress || !buildName.trim()}>
                  {buildInProgress ? (
                    <><Loader2 size={14} className="animate-spin mr-2" /> Building...</>
                  ) : (
                    <><Hammer size={14} className="mr-2" /> Build</>
                  )}
                </Button>
              </>
            ) : (
              <>
                {buildDownloadId && (
                  <Button asChild>
                    <a href={`/api/remote/build/${buildDownloadId}`} download={buildDownloadFilename}>
                      <Download size={14} className="mr-2" />
                      Download {buildDownloadFilename}
                    </a>
                  </Button>
                )}
                <Button
                  variant="outline"
                  onClick={() => {
                    setBuildLog([]);
                    setBuildDownloadId(null);
                  }}
                >
                  {buildDownloadId ? "Build Another" : "Try Again"}
                </Button>
                <Button variant="outline" onClick={() => { setBuildDialogOpen(false); setBuildLog([]); setBuildDownloadId(null); }}>
                  Close
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
