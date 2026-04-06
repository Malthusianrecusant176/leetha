import { useState, useMemo, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { WsMessage } from "@/hooks/use-websocket";
import { toast } from "sonner";
import {
  fetchIncidents, fetchIncidentDetail,
  fetchAlerts,
  bulkAcknowledgeAlerts,
  deleteAllAlerts,
  fetchTrustedBindings, addTrustedBinding, removeTrustedBinding,
  fetchSuppressionRules, addSuppressionRule, removeSuppressionRule,
  type Incident, type IncidentDetail,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import {
  ShieldAlert, Shield, Plus, Search,
  AlertTriangle, Info, X, Settings,
} from "lucide-react";

// ═══════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════

const SUBTYPE_LABELS: Record<string, string> = {
  gateway_impersonation: "Gateway Impersonation",
  ip_conflict: "IP Conflict",
  flip_flop: "ARP Flip-Flop",
  grat_flood: "Gratuitous ARP Flood",
  fingerprint_drift: "Fingerprint Drift",
  oui_mismatch: "OUI Mismatch",
  mac_spoofing: "MAC Spoofing",
  infra_offline: "Infrastructure Offline",
  dhcp_anomaly: "DHCP Anomaly",
  new_device: "New Device",
  os_change: "OS Change",
  mac_randomized: "MAC Randomized",
  unclassified: "Low Confidence",
  source_stale: "Stale Source",
  other: "Network Anomaly",
};

const SEVERITY_COLORS: Record<string, { border: string; bg: string; text: string }> = {
  threat: { border: "border-l-red-500", bg: "bg-red-500/10", text: "text-red-400" },
  suspicious: { border: "border-l-yellow-500", bg: "bg-yellow-500/10", text: "text-yellow-400" },
  informational: { border: "border-l-blue-500", bg: "bg-blue-500/10", text: "text-blue-400" },
};

const SEVERITY_ORDER: Record<string, number> = { threat: 0, suspicious: 1, informational: 2 };

// ═══════════════════════════════════════════
//  Utility helpers
// ═══════════════════════════════════════════

function formatTs(ts: string | null | undefined): string {
  if (!ts) return "-";
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function confColor(c: number): string {
  if (c >= 80) return "hsl(var(--success, 142 76% 36%))";
  if (c >= 50) return "hsl(var(--warning, 38 92% 50%))";
  return "hsl(var(--destructive))";
}

function formatRelative(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

// ═══════════════════════════════════════════
//  Main page — split-pane triage view
// ═══════════════════════════════════════════

interface ThreatDetectionProps {
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

export default function ThreatDetection({ subscribe }: ThreatDetectionProps) {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [configOpen, setConfigOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"severity" | "alerts" | "recent">("severity");

  useEffect(() => {
    return subscribe((msg) => {
      if (msg.type === "finding_created" || msg.device) {
        queryClient.invalidateQueries({ queryKey: ["incidents"] });
      }
    });
  }, [subscribe, queryClient]);

  const { data: incidentData } = useQuery({
    queryKey: ["incidents"],
    queryFn: fetchIncidents,
    staleTime: 10000,
    refetchInterval: 15000,
  });

  const rawCounts = incidentData?.counts ?? {};
  const counts = {
    threat: rawCounts.threat ?? 0,
    suspicious: rawCounts.suspicious ?? 0,
    informational: rawCounts.informational ?? 0,
    total: rawCounts.total ?? 0,
  };
  const findings = incidentData?.incidents ?? [];

  const selectedFinding = findings.find((f) => f.id === selectedId) ?? null;

  return (
    <div className="flex flex-col h-full -m-6">
      {/* Stats bar */}
      <StatsBar
        counts={counts}
        onOpenConfig={() => setConfigOpen(true)}
      />

      {/* Split pane */}
      <div className="flex flex-1 min-h-0">
        <FindingsList
          findings={findings}
          selectedId={selectedId}
          onSelect={setSelectedId}
          severityFilter={severityFilter}
          onSeverityFilter={setSeverityFilter}
          searchQuery={searchQuery}
          onSearch={setSearchQuery}
          sortBy={sortBy}
          onSort={setSortBy}
        />
        <EvidencePanel finding={selectedFinding} />
      </div>

      {/* Config drawer */}
      <ConfigDrawer open={configOpen} onOpenChange={setConfigOpen} />
    </div>
  );
}

// ═══════════════════════════════════════════
//  Stats Bar
// ═══════════════════════════════════════════

function StatsBar({ counts, onOpenConfig }: {
  counts: { threat: number; suspicious: number; informational: number; total: number };
  onOpenConfig: () => void;
}) {
  const queryClient = useQueryClient();
  const [clearAllOpen, setClearAllOpen] = useState(false);

  const handleAcknowledgeAll = async () => {
    try {
      const alerts = await fetchAlerts({ per_page: 9999 });
      const ids = alerts.filter((a) => !a.acknowledged).map((a) => a.id);
      if (ids.length === 0) return;
      await bulkAcknowledgeAlerts(ids);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      toast.success(`Acknowledged ${ids.length} alerts`);
    } catch {
      toast.error("Failed to acknowledge alerts");
    }
  };

  const handleClearAll = async () => {
    try {
      const result = await deleteAllAlerts();
      setClearAllOpen(false);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      toast.success(`Cleared ${result.deleted} alerts`);
    } catch {
      toast.error("Failed to clear alerts");
    }
  };

  return (
    <>
      <div className="flex items-center gap-3 px-6 py-3 border-b border-border flex-wrap">
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
          <AlertTriangle size={13} className="text-red-400" />
          <span className="text-sm font-bold text-red-400">{counts.threat}</span>
          <span className="text-[10px] text-red-400/70">Critical</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
          <ShieldAlert size={13} className="text-yellow-400" />
          <span className="text-sm font-bold text-yellow-400">{counts.suspicious}</span>
          <span className="text-[10px] text-yellow-400/70">Suspicious</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
          <Info size={13} className="text-blue-400" />
          <span className="text-sm font-bold text-blue-400">{counts.informational}</span>
          <span className="text-[10px] text-blue-400/70">Informational</span>
        </div>
        <span className="text-xs text-muted-foreground">{counts.total} findings</span>
        <div className="ml-auto flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={handleAcknowledgeAll} className="text-xs h-7">
            Acknowledge All
          </Button>
          <Button size="sm" variant="outline" onClick={() => setClearAllOpen(true)} className="text-xs h-7 text-destructive hover:text-destructive">
            Clear All
          </Button>
          <button
            onClick={onOpenConfig}
            className="p-1.5 rounded-md hover:bg-accent/50 transition-colors text-muted-foreground hover:text-foreground"
            title="Trusted Bindings & Suppression Rules"
          >
            <Settings size={15} />
          </button>
        </div>
      </div>

      <Dialog open={clearAllOpen} onOpenChange={setClearAllOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Clear All Alerts</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground py-2">
            This will permanently delete all alerts. This action cannot be undone.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setClearAllOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleClearAll}>Delete All</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ═══════════════════════════════════════════
//  Findings List (left panel)
// ═══════════════════════════════════════════

function FindingsList({
  findings,
  selectedId,
  onSelect,
  severityFilter,
  onSeverityFilter,
  searchQuery,
  onSearch,
  sortBy,
  onSort,
}: {
  findings: Incident[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  severityFilter: string;
  onSeverityFilter: (s: string) => void;
  searchQuery: string;
  onSearch: (q: string) => void;
  sortBy: "severity" | "alerts" | "recent";
  onSort: (s: "severity" | "alerts" | "recent") => void;
}) {
  const filtered = useMemo(() => {
    let list = findings;
    if (severityFilter !== "all") {
      list = list.filter((f) => f.severity === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((f) =>
        f.device_mac.toLowerCase().includes(q) ||
        (f.device_ip ?? "").toLowerCase().includes(q) ||
        (f.manufacturer ?? "").toLowerCase().includes(q) ||
        f.subtype.toLowerCase().includes(q)
      );
    }
    const sorted = [...list];
    if (sortBy === "severity") {
      sorted.sort((a, b) => {
        const sa = SEVERITY_ORDER[a.severity] ?? 9;
        const sb = SEVERITY_ORDER[b.severity] ?? 9;
        return sa !== sb ? sa - sb : (b.alert_count ?? 0) - (a.alert_count ?? 0);
      });
    } else if (sortBy === "alerts") {
      sorted.sort((a, b) => (b.alert_count ?? 0) - (a.alert_count ?? 0));
    } else {
      sorted.sort((a, b) => {
        const ta = a.last_seen ?? "";
        const tb = b.last_seen ?? "";
        return tb.localeCompare(ta);
      });
    }
    return sorted;
  }, [findings, severityFilter, searchQuery, sortBy]);

  return (
    <div className="w-[40%] min-w-[280px] border-r border-border flex flex-col">
      {/* Filter controls */}
      <div className="px-3 py-3 border-b border-border space-y-2">
        <div className="flex items-center gap-1.5 flex-wrap">
          {(["all", "threat", "suspicious", "informational"] as const).map((s) => {
            const labels: Record<string, string> = { all: "All", threat: "Critical", suspicious: "Suspicious", informational: "Info" };
            return (
              <button
                key={s}
                onClick={() => onSeverityFilter(s)}
                className={cn(
                  "px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors",
                  severityFilter === s
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
              >
                {labels[s]}
              </button>
            );
          })}
          <select
            value={sortBy}
            onChange={(e) => onSort(e.target.value as "severity" | "alerts" | "recent")}
            className="ml-auto text-[11px] h-7 rounded border border-border bg-background px-2 text-muted-foreground focus:outline-none"
          >
            <option value="severity">Severity</option>
            <option value="alerts">Most alerts</option>
            <option value="recent">Most recent</option>
          </select>
        </div>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50" />
          <input
            type="text"
            placeholder="Filter by MAC, IP, vendor..."
            value={searchQuery}
            onChange={(e) => onSearch(e.target.value)}
            className="w-full h-7 rounded border border-border bg-background pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
      </div>

      {/* Finding cards */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <Shield size={28} className="mb-2 text-muted-foreground/30" />
            <p className="text-xs">No findings match your filters.</p>
          </div>
        ) : (
          filtered.map((f) => {
            const sev = SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS.informational;
            const isSelected = f.id === selectedId;
            const relTime = f.last_seen ? formatRelative(f.last_seen) : "";
            return (
              <button
                key={f.id}
                onClick={() => onSelect(f.id)}
                className={cn(
                  "w-full text-left px-3 py-2.5 border-b border-border border-l-[3px] transition-colors",
                  isSelected
                    ? "bg-accent/30 border-l-primary"
                    : cn("hover:bg-accent/20", sev.border)
                )}
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={cn("text-[10px] font-bold uppercase tracking-wider", sev.text)}>
                    {SUBTYPE_LABELS[f.subtype] ?? f.subtype}
                  </span>
                  {f.is_randomized_mac && (
                    <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 text-cyan-400 border-cyan-400/30">R</Badge>
                  )}
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="font-data text-foreground/80">{f.device_mac}</span>
                  {f.device_ip && <span className="font-data text-muted-foreground">{f.device_ip}</span>}
                </div>
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground mt-0.5">
                  <span>{f.alert_count} alert{f.alert_count !== 1 ? "s" : ""}</span>
                  {relTime && <span>· {relTime}</span>}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Evidence Panel (right panel)
// ═══════════════════════════════════════════

function EvidencePanel({ finding }: { finding: Incident | null }) {
  if (!finding) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground">
        <div className="text-center">
          <Shield size={32} className="mx-auto mb-2 text-muted-foreground/20" />
          <p className="text-sm">Select a finding to review its evidence</p>
        </div>
      </div>
    );
  }

  return <EvidencePanelContent finding={finding} />;
}

function EvidencePanelContent({ finding }: { finding: Incident }) {
  const queryClient = useQueryClient();
  const [suppressOpen, setSuppressOpen] = useState(false);
  const [dismissing, setDismissing] = useState(false);

  const sev = SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.informational;

  const { data: detail, isLoading, error } = useQuery({
    queryKey: ["incident-detail", finding.id],
    queryFn: () => fetchIncidentDetail(finding.id),
    staleTime: 30000,
  });

  const dismissAll = async () => {
    if (finding.alert_ids.length === 0) return;
    setDismissing(true);
    try {
      await bulkAcknowledgeAlerts(finding.alert_ids);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      toast.success(`Dismissed ${finding.alert_ids.length} alerts`);
    } catch {
      toast.error("Failed to dismiss alerts");
    } finally {
      setDismissing(false);
    }
  };

  const markKnown = async () => {
    try {
      await addTrustedBinding(finding.device_mac, finding.device_ip ?? "");
      queryClient.invalidateQueries({ queryKey: ["trusted-bindings"] });
      toast.success("Device marked as known");
    } catch {
      toast.error("Failed to mark as known");
    }
  };

  return (
    <div className="flex-1 overflow-y-auto">
      {/* Finding header */}
      <div className={cn("px-6 py-4 border-b border-border border-l-4", sev.border)}>
        <div className="flex items-center gap-2 mb-2">
          <span className={cn("text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded", sev.bg, sev.text)}>
            {finding.severity}
          </span>
          <span className="text-sm font-semibold">
            {SUBTYPE_LABELS[finding.subtype] ?? finding.subtype}
          </span>
          <span className="text-xs text-muted-foreground ml-auto">
            {finding.alert_count} alert{finding.alert_count !== 1 ? "s" : ""}
          </span>
        </div>
        <div className="flex items-center gap-3 text-sm flex-wrap">
          <span className="font-data text-foreground">{finding.device_mac}</span>
          {finding.device_ip && <span className="font-data text-muted-foreground">{finding.device_ip}</span>}
          {finding.manufacturer && <span className="text-muted-foreground">{finding.manufacturer}</span>}
        </div>
        {finding.is_randomized_mac && (
          <div className="mt-1.5 text-xs text-cyan-400">Randomized MAC — identity changes expected</div>
        )}
        {!finding.is_randomized_mac && finding.correlated_mac && (
          <div className="mt-1.5 text-xs text-cyan-400">Correlated to {finding.correlated_mac}</div>
        )}
        <div className="flex items-center gap-2 mt-3">
          <Button size="sm" variant="outline" onClick={dismissAll} disabled={dismissing || finding.alert_ids.length === 0} className="text-xs h-7">
            Dismiss All
          </Button>
          <Button size="sm" variant="outline" onClick={() => setSuppressOpen(true)} className="text-xs h-7">
            Suppress
          </Button>
          <Button size="sm" variant="outline" onClick={markKnown} className="text-xs h-7">
            Mark Known
          </Button>
        </div>
      </div>

      {/* Evidence body */}
      {isLoading ? (
        <div className="px-6 py-8">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-1/3" />
            <div className="h-20 bg-muted rounded" />
            <div className="h-4 bg-muted rounded w-1/2" />
          </div>
        </div>
      ) : error || !detail ? (
        <div className="px-6 py-8 text-sm text-destructive">Failed to load evidence.</div>
      ) : (
        <EvidenceSections detail={detail} />
      )}

      <SuppressionDialog
        open={suppressOpen}
        mac={finding.device_mac}
        subtype={finding.subtype}
        onClose={() => setSuppressOpen(false)}
      />
    </div>
  );
}

// ═══════════════════════════════════════════
//  Evidence Sections
// ═══════════════════════════════════════════

function EvidenceSections({ detail }: { detail: IncidentDetail }) {
  const ctx = detail.detection_context;
  const device = detail.device as Record<string, unknown>;

  const recLower = (ctx.recommendation ?? "").toLowerCase();
  const recStyle = recLower.includes("critical") || recLower.includes("immediate")
    ? "bg-red-500/10 border-red-500/30 text-red-300"
    : recLower.includes("investigate") || recLower.includes("review") || recLower.includes("monitor")
      ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-300"
      : "bg-green-500/10 border-green-500/30 text-green-300";

  return (
    <div className="px-6 py-5 space-y-6">
      {/* Detection Context */}
      <DetailSection title="Detection Context">
        <p className="text-sm text-foreground/90 mb-1">{ctx.trigger}</p>
        <p className="text-xs text-muted-foreground mb-2">{ctx.method}</p>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          {device.first_seen && <span>Discovered: <span className="font-data">{formatTs(String(device.first_seen))}</span></span>}
          {device.confidence != null && (
            <span>Confidence: <span className="font-bold" style={{ color: confColor(Number(device.confidence)) }}>{Number(device.confidence)}%</span></span>
          )}
        </div>
      </DetailSection>

      {/* Analyst Notes */}
      {ctx.recommendation && (
        <DetailSection title="Analyst Notes">
          <div className={cn("rounded-lg border px-4 py-3 text-sm", recStyle)}>
            {ctx.recommendation}
          </div>
        </DetailSection>
      )}

      {/* ARP History */}
      {(detail.arp_history?.length ?? 0) > 0 && (
        <DetailSection title={`ARP History (${detail.arp_history.length})`}>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="bg-secondary/50 border-b border-border">
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">IP</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">Interface</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">Pkts</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">Grat</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">First</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-muted-foreground">Last</th>
                </tr>
              </thead>
              <tbody>
                {detail.arp_history.map((ah, i) => {
                  const a = ah as Record<string, unknown>;
                  return (
                    <tr key={i} className="border-b border-border/50">
                      <td className="px-3 py-1.5 font-data text-xs">{String(a.ip ?? "-")}</td>
                      <td className="px-3 py-1.5 text-xs">{String(a.interface ?? "-")}</td>
                      <td className="px-3 py-1.5 text-xs">{String(a.packet_count ?? "-")}</td>
                      <td className="px-3 py-1.5 text-xs">{a.is_gratuitous ? "Yes" : "No"}</td>
                      <td className="px-3 py-1.5 text-[10px] text-muted-foreground">{formatTs(String(a.first_seen ?? ""))}</td>
                      <td className="px-3 py-1.5 text-[10px] text-muted-foreground">{formatTs(String(a.last_seen ?? ""))}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </DetailSection>
      )}

      {/* Fingerprint History */}
      {(detail.fingerprint_history?.length ?? 0) > 0 && (
        <DetailSection title={`Fingerprint History (${detail.fingerprint_history.length})`}>
          <div className="space-y-1.5 max-h-[250px] overflow-y-auto">
            {detail.fingerprint_history.map((fh, i) => {
              const h = fh as Record<string, unknown>;
              return (
                <div key={i} className="flex items-center gap-4 px-3 py-2 rounded-lg bg-card border border-border text-xs">
                  <span className="text-muted-foreground font-data min-w-[140px]">{formatTs(String(h.timestamp ?? ""))}</span>
                  <span className="text-foreground">{String(h.os_family ?? "-")}</span>
                  <span className="text-muted-foreground">{String(h.manufacturer ?? "-")}</span>
                  <span className="text-muted-foreground">{String(h.device_type ?? "-")}</span>
                  {h.hostname ? <span className="text-muted-foreground font-data">{String(h.hostname)}</span> : null}
                </div>
              );
            })}
          </div>
        </DetailSection>
      )}

      {/* Fingerprint Evidence */}
      {(detail.evidence?.length ?? 0) > 0 && (
        <DetailSection title={`Fingerprint Evidence (${detail.evidence.length})`}>
          <div className="space-y-2 max-h-[300px] overflow-y-auto">
            {detail.evidence.map((ev, i) => {
              const e = ev as Record<string, unknown>;
              const source = String(e.source ?? "");
              const conf = Number(e.confidence ?? 0);
              const fields: Array<[string, string]> = [];
              if (e.manufacturer) fields.push(["Vendor", String(e.manufacturer)]);
              if (e.device_type) fields.push(["Category", String(e.device_type)]);
              if (e.os_family) fields.push(["Platform", String(e.os_family)]);
              if (e.os_version) fields.push(["Version", String(e.os_version)]);
              return (
                <div key={i} className="rounded-lg bg-card border border-border p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-semibold text-cyan-400">{source}</span>
                    <span className="text-xs font-bold" style={{ color: confColor(conf) }}>{conf}%</span>
                  </div>
                  {fields.length > 0 && (
                    <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                      {fields.map(([k, v]) => (
                        <div key={k}>
                          <span className="text-[9px] text-muted-foreground">{k}</span>
                          <div className="text-[11px]">{v}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </DetailSection>
      )}

      {/* Recent Observations */}
      {(detail.recent_observations?.length ?? 0) > 0 && (
        <DetailSection title={`Recent Observations (${Math.min(detail.recent_observations.length, 10)})`}>
          <div className="space-y-1 max-h-[250px] overflow-y-auto">
            {detail.recent_observations.slice(0, 10).map((obs, i) => {
              const o = obs as Record<string, unknown>;
              return (
                <div key={i} className={cn("flex items-start gap-3 px-3 py-1.5 rounded text-xs", i % 2 === 0 ? "bg-card" : "bg-secondary/20")}>
                  <span className="w-1.5 h-1.5 rounded-full bg-primary shrink-0 mt-1" />
                  <span className="text-muted-foreground font-data min-w-[130px]">{formatTs(String(o.timestamp ?? ""))}</span>
                  <span className="font-medium min-w-[80px]">{String(o.source_type ?? "-")}</span>
                  <span className="text-muted-foreground flex-1 break-all font-data">
                    {o.raw_data ? (typeof o.raw_data === "string" ? o.raw_data : JSON.stringify(o.raw_data)).substring(0, 120) : "-"}
                  </span>
                </div>
              );
            })}
          </div>
        </DetailSection>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════
//  Config Drawer
// ═══════════════════════════════════════════

function ConfigDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[500px] sm:w-[540px] overflow-y-auto">
        <SheetHeader>
          <SheetTitle>Detection Config</SheetTitle>
        </SheetHeader>
        <div className="space-y-6 mt-4">
          <TrustedBindingsPanel />
          <SuppressionsPanel />
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ═══════════════════════════════════════════
//  Suppression Dialog (preserved)
// ═══════════════════════════════════════════

function SuppressionDialog({
  open,
  mac,
  subtype,
  onClose,
}: {
  open: boolean;
  mac: string;
  subtype: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [fpSubtype, setFpSubtype] = useState(subtype);
  const [fpReason, setFpReason] = useState("");

  // Sync subtype when dialog opens with new values
  const [prevMac, setPrevMac] = useState(mac);
  if (mac !== prevMac) {
    setPrevMac(mac);
    setFpSubtype(subtype);
    setFpReason("");
  }

  const submit = async () => {
    try {
      const rule: Record<string, string> = { mac };
      if (fpSubtype) rule.subtype = fpSubtype;
      if (fpReason.trim()) rule.reason = fpReason.trim();
      await addSuppressionRule(rule);
      queryClient.invalidateQueries({ queryKey: ["suppression-rules"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      onClose();
      toast.success("Suppression rule created");
    } catch {
      toast.error("Failed to create rule");
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Create Suppression Rule</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Hardware Address</label>
            <Input value={mac} readOnly className="font-data bg-secondary" />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Subtype</label>
            <select
              value={fpSubtype}
              onChange={(e) => setFpSubtype(e.target.value)}
              className="w-full h-9 rounded border border-border bg-background px-3 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">Any subtype</option>
              <option value="gateway_impersonation">Gateway Impersonation</option>
              <option value="ip_conflict">IP Conflict</option>
              <option value="grat_flood">Gratuitous Flood</option>
              <option value="flip_flop">Flip-Flop</option>
              <option value="fingerprint_drift">Fingerprint Drift</option>
              <option value="oui_mismatch">OUI Mismatch</option>
              <option value="dhcp_anomaly">DHCP Anomaly</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Reason</label>
            <Input value={fpReason} onChange={(e) => setFpReason(e.target.value)} placeholder="Why should this be suppressed?" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={submit}>Create Rule</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════
//  Trusted Bindings Panel (preserved)
// ═══════════════════════════════════════════

function TrustedBindingsPanel() {
  const queryClient = useQueryClient();
  const [mac, setMac] = useState("");
  const [ip, setIp] = useState("");
  const { data: bindings = [] } = useQuery({ queryKey: ["trusted-bindings"], queryFn: fetchTrustedBindings });

  const add = async () => {
    if (!mac.trim() || !ip.trim()) { toast.error("Both MAC and IP required"); return; }
    try { await addTrustedBinding(mac.trim(), ip.trim()); queryClient.invalidateQueries({ queryKey: ["trusted-bindings"] }); setMac(""); setIp(""); toast.success("Added"); } catch { toast.error("Failed"); }
  };
  const remove = async (m: string) => {
    try { await removeTrustedBinding(m); queryClient.invalidateQueries({ queryKey: ["trusted-bindings"] }); toast.success("Removed"); } catch { toast.error("Failed"); }
  };

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-3 border-b border-border"><h3 className="text-sm font-semibold">Trusted Bindings</h3></div>
      <div className="p-5">
        <div className="flex gap-2 mb-4">
          <Input placeholder="Hardware address" value={mac} onChange={(e) => setMac(e.target.value)} className="flex-1 font-data" />
          <Input placeholder="Network address" value={ip} onChange={(e) => setIp(e.target.value)} className="flex-1 font-data" />
          <Button onClick={add}><Plus size={14} className="mr-1" /> Add</Button>
        </div>
        {bindings.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4 text-center">No trusted bindings configured.</p>
        ) : (
          <div className="divide-y divide-border rounded-lg border border-border">
            {bindings.map((b) => (
              <div key={b.mac} className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-3">
                  <span className="font-data text-sm">{b.mac}</span>
                  <span className="text-muted-foreground text-sm">{b.ip}</span>
                </div>
                <button className="text-xs text-destructive hover:text-destructive/80 transition-colors" onClick={() => remove(b.mac)}>Remove</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Suppression Rules Panel (preserved)
// ═══════════════════════════════════════════

function SuppressionsPanel() {
  const queryClient = useQueryClient();
  const [fMac, setFMac] = useState("");
  const [fIp, setFIp] = useState("");
  const [fSub, setFSub] = useState("");
  const [fReason, setFReason] = useState("");
  const { data: rules = [] } = useQuery({ queryKey: ["suppression-rules"], queryFn: fetchSuppressionRules });

  const add = async () => {
    const r: Record<string, string> = {};
    if (fMac.trim()) r.mac = fMac.trim();
    if (fIp.trim()) r.ip = fIp.trim();
    if (fSub) r.subtype = fSub;
    if (fReason.trim()) r.reason = fReason.trim();
    if (!r.mac && !r.ip && !r.subtype) { toast.error("Need at least MAC, IP, or subtype"); return; }
    try { await addSuppressionRule(r); queryClient.invalidateQueries({ queryKey: ["suppression-rules"] }); setFMac(""); setFIp(""); setFSub(""); setFReason(""); toast.success("Added"); } catch { toast.error("Failed"); }
  };
  const remove = async (id: number) => {
    try { await removeSuppressionRule(id); queryClient.invalidateQueries({ queryKey: ["suppression-rules"] }); toast.success("Removed"); } catch { toast.error("Failed"); }
  };

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-3 border-b border-border"><h3 className="text-sm font-semibold">Suppression Rules</h3></div>
      <div className="p-5">
        <div className="flex gap-2 mb-4 flex-wrap">
          <Input placeholder="MAC (optional)" value={fMac} onChange={(e) => setFMac(e.target.value)} className="flex-1 min-w-[120px] font-data" />
          <Input placeholder="IP (optional)" value={fIp} onChange={(e) => setFIp(e.target.value)} className="flex-1 min-w-[100px] font-data" />
          <select value={fSub} onChange={(e) => setFSub(e.target.value)} className="flex-1 min-w-[140px] h-9 rounded border border-border bg-background px-3 text-sm focus:outline-none focus:ring-1 focus:ring-primary">
            <option value="">Any subtype</option>
            <option value="gateway_impersonation">Gateway Impersonation</option>
            <option value="ip_conflict">IP Conflict</option>
            <option value="grat_flood">Gratuitous Flood</option>
            <option value="flip_flop">Flip-Flop</option>
            <option value="fingerprint_drift">Fingerprint Drift</option>
            <option value="oui_mismatch">OUI Mismatch</option>
            <option value="dhcp_anomaly">DHCP Anomaly</option>
          </select>
          <Input placeholder="Reason" value={fReason} onChange={(e) => setFReason(e.target.value)} className="flex-[2] min-w-[120px]" />
          <Button onClick={add}><Plus size={14} className="mr-1" /> Add</Button>
        </div>
        {rules.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4 text-center">No suppression rules. Use &quot;False Positive&quot; on an alert to create one.</p>
        ) : (
          <div className="divide-y divide-border rounded-lg border border-border">
            {rules.map((r) => (
              <div key={r.id} className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-2 flex-wrap text-sm">
                  {r.mac && <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-secondary border border-border">MAC: {r.mac}</span>}
                  {r.ip && <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-secondary border border-border">IP: {r.ip}</span>}
                  {r.subtype && <span className="text-[11px] px-1.5 py-0.5 rounded bg-secondary border border-border">{r.subtype}</span>}
                  {r.reason && <span className="text-muted-foreground ml-1">{r.reason}</span>}
                </div>
                <button className="text-xs text-destructive hover:text-destructive/80 transition-colors shrink-0" onClick={() => remove(r.id)}>Remove</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Shared helpers (preserved)
// ═══════════════════════════════════════════

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="text-xs font-bold uppercase tracking-[0.15em] text-muted-foreground mb-3">{title}</h4>
      {children}
    </section>
  );
}
