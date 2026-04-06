import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchPatterns,
  addPattern,
  deletePattern,
  type PatternEntry,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Trash2, Plus, Fingerprint } from "lucide-react";

const PATTERN_TYPES = ["hostname", "dhcp_opt60", "mac_prefix"] as const;

const typeLabels: Record<string, string> = {
  hostname: "Hostname",
  dhcp_opt60: "DHCP Option 60",
  mac_prefix: "MAC Prefix",
};

export default function Patterns() {
  const queryClient = useQueryClient();

  const { data: patterns = {} } = useQuery({
    queryKey: ["patterns"],
    queryFn: fetchPatterns,
  });

  // Add-pattern form state
  const [formType, setFormType] = useState<string>("hostname");
  const [formPattern, setFormPattern] = useState("");
  const [formDeviceType, setFormDeviceType] = useState("");
  const [formManufacturer, setFormManufacturer] = useState("");
  const [formConfidence, setFormConfidence] = useState("80");
  const [submitting, setSubmitting] = useState(false);

  const handleAdd = async () => {
    if (!formPattern.trim() || !formDeviceType.trim()) {
      toast.error("Pattern and device type are required.");
      return;
    }
    setSubmitting(true);
    try {
      const entry: PatternEntry = {
        pattern: formPattern.trim(),
        device_type: formDeviceType.trim(),
        manufacturer: formManufacturer.trim(),
        confidence: Number(formConfidence) || 80,
      };
      await addPattern(formType, entry);
      toast.success(`Added ${typeLabels[formType] ?? formType} pattern`);
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
      // Reset form
      setFormPattern("");
      setFormDeviceType("");
      setFormManufacturer("");
      setFormConfidence("80");
    } catch (err) {
      toast.error(`Failed to add pattern: ${err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (type: string, index: number) => {
    try {
      await deletePattern(type, index);
      toast.success("Pattern deleted");
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
    } catch (err) {
      toast.error(`Failed to delete pattern: ${err}`);
    }
  };

  const totalPatterns = Object.values(patterns).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Custom Fingerprint Patterns</h2>
        <Badge variant="outline">{totalPatterns} pattern(s)</Badge>
      </div>

      {/* Add pattern form */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Plus size={16} />
            Add Pattern
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Type</label>
              <Select value={formType} onValueChange={setFormType}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PATTERN_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {typeLabels[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Pattern</label>
              <Input
                placeholder="e.g. *printer*"
                value={formPattern}
                onChange={(e) => setFormPattern(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Host Category</label>
              <Input
                placeholder="e.g. Printer"
                value={formDeviceType}
                onChange={(e) => setFormDeviceType(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Vendor</label>
              <Input
                placeholder="e.g. HP"
                value={formManufacturer}
                onChange={(e) => setFormManufacturer(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Certainty (0-100)</label>
              <div className="flex gap-2">
                <Input
                  type="number"
                  min={0}
                  max={100}
                  value={formConfidence}
                  onChange={(e) => setFormConfidence(e.target.value)}
                  className="w-20"
                />
                <Button onClick={handleAdd} disabled={submitting} className="flex-shrink-0">
                  <Plus size={14} className="mr-1" />
                  Add
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Pattern groups */}
      {PATTERN_TYPES.map((type) => {
        const entries = patterns[type] ?? [];
        if (entries.length === 0) return null;

        return (
          <Card key={type}>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Fingerprint size={16} />
                {typeLabels[type]}
                <Badge variant="secondary" className="ml-2">
                  {entries.length}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Pattern</TableHead>
                    <TableHead>Host Category</TableHead>
                    <TableHead>Vendor</TableHead>
                    <TableHead className="w-24">Certainty</TableHead>
                    <TableHead className="w-16"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.map((entry, index) => (
                    <TableRow key={index}>
                      <TableCell className="font-data text-sm">{entry.pattern}</TableCell>
                      <TableCell>{entry.device_type}</TableCell>
                      <TableCell>{entry.manufacturer || "—"}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{entry.confidence}%</Badge>
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete(type, index)}
                          className="text-destructive hover:text-destructive"
                        >
                          <Trash2 size={14} />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        );
      })}

      {/* Show remaining types not in PATTERN_TYPES */}
      {Object.entries(patterns)
        .filter(([type]) => !(PATTERN_TYPES as readonly string[]).includes(type))
        .map(([type, entries]) => {
          if (entries.length === 0) return null;
          return (
            <Card key={type}>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Fingerprint size={16} />
                  {type}
                  <Badge variant="secondary" className="ml-2">
                    {entries.length}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Pattern</TableHead>
                      <TableHead>Host Category</TableHead>
                      <TableHead>Vendor</TableHead>
                      <TableHead className="w-24">Certainty</TableHead>
                      <TableHead className="w-16"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {entries.map((entry, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-data text-sm">{entry.pattern}</TableCell>
                        <TableCell>{entry.device_type}</TableCell>
                        <TableCell>{entry.manufacturer || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{entry.confidence}%</Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(type, index)}
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 size={14} />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          );
        })}

      {totalPatterns === 0 && (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Fingerprint size={32} className="mb-2" />
          <p className="font-medium">No custom patterns defined</p>
          <p className="text-xs">Add a pattern above to get started.</p>
        </div>
      )}
    </div>
  );
}
