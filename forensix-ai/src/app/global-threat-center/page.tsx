"use client";

import AppLayout from "@/components/AppLayout";
import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import dynamic from "next/dynamic";
import {
  Globe, Shield, AlertTriangle, Activity, Search, RefreshCw, Zap,
  Clock, Filter, Database, Link2, Eye, Server, Cpu, Flame, Layers, X,
  ChevronLeft, ChevronRight, Play, Pause, Sun, Moon, Maximize2, RotateCcw,
  AlertOctagon, HelpCircle, Download, FileCode, CheckCircle, Smartphone, Wifi, Lock
} from "lucide-react";

// Dynamically import ECharts-for-React to prevent server-side rendering issues in Next.js
const ReactECharts = dynamic(() => import("echarts-for-react"), { ssr: false });

// Interfaces
interface ThreatEvent {
  id: string;
  name: string;
  type: string;
  category: string;
  target_device: string;
  target_platform: string;
  os: string;
  industry: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  source_country: string;
  source_code: string;
  destination_country: string;
  destination_code: string;
  ip: string;
  domain: string;
  malware_family: string;
  exploit_used: string;
  mitre_technique: string;
  cve_number: string;
  attack_time: string;
  detection_time: string;
  affected_users: number;
  affected_systems: number;
  risk_score: number;
  ioc: string;
  hash: string;
  file_name: string;
  protocol: string;
  port: number;
  attack_vector: string;
  recommendation: string;
  response_status: string;
  soc_notes: string;
}

interface ActiveLaser {
  id: string;
  srcCode: string;
  dstCode: string;
  srcX: number;
  srcY: number;
  dstX: number;
  dstY: number;
  color: string;
  severity: string;
  type: string;
}

interface ToastAlert {
  id: string;
  message: string;
  severity: string;
}

// Centroids for major countries to anchor lasers and markers
const COUNTRY_METADATA: Record<string, { name: string; flag: string; lon: number; lat: number }> = {
  USA: { name: "United States", flag: "🇺🇸", lon: -100, lat: 40 },
  CAN: { name: "Canada", flag: "🇨🇦", lon: -100, lat: 60 },
  BRA: { name: "Brazil", flag: "🇧🇷", lon: -55, lat: -10 },
  GBR: { name: "United Kingdom", flag: "🇬🇧", lon: -2, lat: 54 },
  FRA: { name: "France", flag: "🇫🇷", lon: 2, lat: 46 },
  DEU: { name: "Germany", flag: "🇩🇪", lon: 10, lat: 51 },
  RUS: { name: "Russia", flag: "🇷🇺", lon: 95, lat: 60 },
  CHN: { name: "China", flag: "🇨🇳", lon: 105, lat: 35 },
  IND: { name: "India", flag: "🇮🇳", lon: 78, lat: 21 },
  AUS: { name: "Australia", flag: "🇦🇺", lon: 133, lat: -25 },
  ZAF: { name: "South Africa", flag: "🇿🇦", lon: 24, lat: -29 },
  JPN: { name: "Japan", flag: "🇯🇵", lon: 138, lat: 36 },
  KOR: { name: "South Korea", flag: "🇰🇷", lon: 127, lat: 36 },
  SGP: { name: "Singapore", flag: "🇸🇬", lon: 103.8, lat: 1.3 },
  UKR: { name: "Ukraine", flag: "🇺🇦", lon: 31, lat: 49 },
  IRN: { name: "Iran", flag: "🇮🇷", lon: 53, lat: 32 },
  ISR: { name: "Israel", flag: "🇮🇱", lon: 35, lat: 31 },
  NLD: { name: "Netherlands", flag: "🇳🇱", lon: 5, lat: 52 },
  POL: { name: "Poland", flag: "🇵🇱", lon: 19, lat: 52 },
  SWE: { name: "Sweden", flag: "🇸🇪", lon: 18, lat: 60 },
  NOR: { name: "Norway", flag: "🇳🇴", lon: 8, lat: 60 },
  FIN: { name: "Finland", flag: "🇫🇮", lon: 26, lat: 62 },
  ITA: { name: "Italy", flag: "🇮🇹", lon: 12, lat: 42 },
  ESP: { name: "Spain", flag: "🇪🇸", lon: -3, lat: 40 },
  TUR: { name: "Turkey", flag: "🇹🇷", lon: 35, lat: 39 },
  SAU: { name: "Saudi Arabia", flag: "🇸🇦", lon: 45, lat: 24 },
  ARE: { name: "United Arab Emirates", flag: "🇦🇪", lon: 54, lat: 24 },
  EGY: { name: "Egypt", flag: "🇪🇬", lon: 30, lat: 26 },
  MEX: { name: "Mexico", flag: "🇲🇽", lon: -102, lat: 23 },
  ARG: { name: "Argentina", flag: "🇦🇷", lon: -65, lat: -35 },
};

const ATTACK_TYPES = [
  "Ransomware", "DDoS", "Phishing", "Credential Stuffing", "Brute Force",
  "SQL Injection", "XSS", "Zero-Day", "Remote Code Execution", "Malware",
  "Trojan", "Spyware", "Worm", "Rootkit", "Botnet", "Insider Threat",
  "Supply Chain Attack", "APT", "Cryptojacking", "DNS Attack", "MITM", "Data Exfiltration"
];

const SEVERITIES: ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW")[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const INDUSTRIES = [
  "Finance", "Healthcare", "Energy", "Government", "Technology",
  "Retail", "Manufacturing", "Defense", "Education", "Telecommunications"
];

const DEVICE_TYPES = [
  { name: "Fin-Dept-Server", platform: "Windows Server 2022", os: "Windows Server", type: "Server" },
  { name: "HR-Portal-VM", platform: "Ubuntu 22.04 LTS", os: "Linux", type: "Cloud VM" },
  { name: "Executive-Laptop", platform: "macOS Sequoia", os: "macOS", type: "Laptop" },
  { name: "SOC-Firewall-Primary", platform: "FortiOS 7.4", os: "Proprietary", type: "Firewall" },
  { name: "Core-Switch-1", platform: "Cisco IOS-XE", os: "Proprietary", type: "Router" },
  { name: "Smart-Meter-IoT", platform: "FreeRTOS", os: "Embedded Linux", type: "IoT" },
  { name: "Staff-Mobile", platform: "Android 14", os: "Android", type: "Mobile" },
  { name: "Billing-DB-Primary", platform: "Windows Server 2019", os: "Windows Server", type: "Server" },
];

const MALWARE_FAMILIES = [
  "LockBit 3.0", "Cobalt Strike", "Emotet", "AgentTesla", "RedLine Stealer",
  "Qakbot", "Anubis", "Mirai", "WannaCry", "Pegasus", "TrickBot"
];

const ATTACK_VECTORS = [
  "Phishing Email", "Compromised Credentials", "Software Vulnerability",
  "Drive-by Download", "Malicious USB", "Insider Abuse", "Third-Party Vendor"
];

// Helper to project spherical coordinates (lon, lat) using Miller Cylindrical Projection onto [0, 1000] x [0, 500] SVG space
function projectMiller(lon: number, lat: number, width = 1000, height = 500): [number, number] {
  const x = ((lon + 180) * width) / 360;
  const cappedLat = Math.max(-85, Math.min(85, lat));
  const cappedLatRad = (cappedLat * Math.PI) / 180;
  const yVal = 1.25 * Math.log(Math.tan(Math.PI / 4 + 0.4 * cappedLatRad));
  const y = height / 2 - (height * yVal) / 4.6;
  return [x, y];
}

// Generate 1000+ detailed simulated threats
function generateThreatDatabase(): ThreatEvent[] {
  const db: ThreatEvent[] = [];
  const baseTime = new Date();
  baseTime.setHours(14, 0, 0, 0);

  const countryKeys = Object.keys(COUNTRY_METADATA);

  for (let i = 0; i < 1150; i++) {
    const id = `THR-${10000 + i}`;
    const type = ATTACK_TYPES[i % ATTACK_TYPES.length];
    const industry = INDUSTRIES[i % INDUSTRIES.length];
    const dev = DEVICE_TYPES[i % DEVICE_TYPES.length];
    const malware = MALWARE_FAMILIES[i % MALWARE_FAMILIES.length];
    const vector = ATTACK_VECTORS[i % ATTACK_VECTORS.length];

    const srcIndex = (i * 7) % countryKeys.length;
    let dstIndex = (i * 13) % countryKeys.length;
    if (srcIndex === dstIndex) dstIndex = (dstIndex + 1) % countryKeys.length;

    const srcCode = countryKeys[srcIndex];
    const dstCode = countryKeys[dstIndex];
    const srcCountry = COUNTRY_METADATA[srcCode];
    const dstCountry = COUNTRY_METADATA[dstCode];

    const severity = i % 12 === 0 ? "CRITICAL" : i % 4 === 0 ? "HIGH" : i % 2 === 0 ? "MEDIUM" : "LOW";
    const status = i % 7 === 0 ? "Active" : i % 4 === 0 ? "Investigating" : "Blocked";
    const risk = severity === "CRITICAL" ? 90 + (i % 10) : severity === "HIGH" ? 72 + (i % 18) : severity === "MEDIUM" ? 45 + (i % 27) : 12 + (i % 33);

    const eventTime = new Date(baseTime.getTime() + i * 23000);
    const timeStr = eventTime.toTimeString().split(" ")[0];

    db.push({
      id,
      name: `${type} Alert targeting ${dev.name}`,
      type,
      category: type === "Phishing" ? "Social Engineering" : type === "DDoS" ? "Availability Denial" : "Intrusion",
      target_device: dev.name,
      target_platform: dev.platform,
      os: dev.os,
      industry,
      severity,
      status,
      source_country: srcCountry?.name || "Unknown",
      source_code: srcCode,
      destination_country: dstCountry?.name || "Unknown",
      destination_code: dstCode,
      ip: `185.234.219.${(i * 3) % 255}`,
      domain: `${malware.toLowerCase().replace(/[^a-z0-9]/g, "")}-c2-${i % 25}.com`,
      malware_family: ["Malware", "Ransomware", "Trojan", "Spyware", "Worm", "Botnet"].includes(type) ? malware : "N/A",
      exploit_used: i % 3 === 0 ? `CVE-2024-${1000 + (i % 8999)}` : "None",
      mitre_technique: type === "Ransomware" ? "T1486 (Data Encrypted)" : type === "Phishing" ? "T1566 (Phishing)" : "T1210 (Exploitation)",
      cve_number: i % 3 === 0 ? `CVE-2024-${1000 + (i % 8999)}` : "N/A",
      attack_time: timeStr,
      detection_time: timeStr,
      affected_users: (i % 38) + 1,
      affected_systems: (i % 9) + 1,
      risk_score: risk,
      ioc: `MD5:${Math.random().toString(16).substring(2, 10)}...`,
      hash: `sha256:${Math.random().toString(16).substring(2, 18)}...`,
      file_name: ["Malware", "Ransomware", "Trojan"].includes(type) ? `${malware.toLowerCase().replace(/\s/g, "_")}_agent.bin` : "N/A",
      protocol: i % 2 === 0 ? "TCP" : "HTTPS",
      port: i % 2 === 0 ? 8080 : 443,
      attack_vector: vector,
      recommendation: `Isolate device ${dev.name} immediately and run anti-malware sweep.`,
      response_status: status === "Blocked" ? "Mitigated" : "Quarantined",
      soc_notes: `Signature trigger at host level: ${dev.name} running ${dev.os}.`
    });
  }

  return db;
}

export default function GlobalThreatCenterPage() {
  const [geoData, setGeoData] = useState<any>(null);
  const [threatDb, setThreatDb] = useState<ThreatEvent[]>([]);
  const [activeLasers, setActiveLasers] = useState<ActiveLaser[]>([]);
  const [toasts, setToasts] = useState<ToastAlert[]>([]);
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);

  // Map Controls State
  const [zoom, setZoom] = useState(1.1);
  const [pan, setPan] = useState({ x: -40, y: 15 });
  const [mapStyle, setMapStyle] = useState<"night" | "satellite">("night");
  const [heatmapEnabled, setHeatmapEnabled] = useState(false);
  const [clusterView, setClusterView] = useState(false);
  const [replayMode, setReplayMode] = useState(true);
  const [timeProgress, setTimeProgress] = useState(50); // Slider progress

  // Dragging parameters
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Filters State
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterType, setFilterType] = useState<string>("ALL");
  const [filterCountry, setFilterCountry] = useState<string>("ALL");
  const [filterOS, setFilterOS] = useState<string>("ALL");
  const [filterIndustry, setFilterIndustry] = useState<string>("ALL");
  const [filterMalware, setFilterMalware] = useState<string>("ALL");
  const [filterVector, setFilterVector] = useState<string>("ALL");
  const [filterDevice, setFilterDevice] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Country Detail Table Pagination
  const [tablePage, setTablePage] = useState(1);
  const [tableSortColumn, setTableSortColumn] = useState<keyof ThreatEvent>("attack_time");
  const [tableSortDir, setTableSortDir] = useState<"asc" | "desc">("desc");

  // Live Stats Counters
  const [liveStats, setLiveStats] = useState({
    totalThreats: 184200,
    attacksPerSecond: 28.4,
    countriesUnderAttack: 12,
    activeBotnets: 184,
    malwareCampaigns: 42,
    compromisedDevices: 8940,
    successfulAttacks: 210,
    blockedAttacks: 184000
  });

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const mapContainerRef = useRef<HTMLDivElement | null>(null);

  // Fetch GeoJSON map boundaries
  useEffect(() => {
    fetch("/world-countries.json")
      .then((res) => {
        if (!res.ok) throw new Error("GeoJSON not loaded");
        return res.json();
      })
      .then((data) => setGeoData(data))
      .catch((err) => console.error("Error fetching map:", err));

    setThreatDb(generateThreatDatabase());
  }, []);

  // Background animated particle grid
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animFrameId: number;
    let particles: { x: number; y: number; vx: number; vy: number; size: number; alpha: number }[] = [];

    const handleResize = () => {
      if (canvas.parentElement) {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
      }
    };
    handleResize();
    window.addEventListener("resize", handleResize);

    // Seed cyber-particles
    for (let i = 0; i < 70; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: Math.random() * 2 + 1,
        alpha: Math.random() * 0.4 + 0.1
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        ctx.fillStyle = `rgba(0, 242, 254, ${p.alpha})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
      });

      animFrameId = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(animFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  // Live Attack Stream Loop (WebSocket emulation or real triggers)
  useEffect(() => {
    if (!replayMode || threatDb.length === 0) return;

    const streamInterval = setInterval(() => {
      // Pick a random event to launch as laser line
      const event = threatDb[Math.floor(Math.random() * threatDb.length)];
      const srcMeta = COUNTRY_METADATA[event.source_code];
      const dstMeta = COUNTRY_METADATA[event.destination_code];

      if (srcMeta && dstMeta) {
        const [srcX, srcY] = projectMiller(srcMeta.lon, srcMeta.lat);
        const [dstX, dstY] = projectMiller(dstMeta.lon, dstMeta.lat);

        const newLaser: ActiveLaser = {
          id: Math.random().toString(),
          srcCode: event.source_code,
          dstCode: event.destination_code,
          srcX,
          srcY,
          dstX,
          dstY,
          color: event.severity === "CRITICAL" ? "#ef4444" : event.severity === "HIGH" ? "#f97316" : "#eab308",
          severity: event.severity,
          type: event.type
        };

        setActiveLasers((prev) => [...prev.slice(-15), newLaser]); // Keep last 15 active laser paths

        // Remove laser after 1.5 seconds to make it clean
        setTimeout(() => {
          setActiveLasers((prev) => prev.filter((l) => l.id !== newLaser.id));
        }, 1500);

        // Periodically show real-time notification toasts (for high/critical attacks)
        if (Math.random() > 0.4) {
          const toastEmoji = event.severity === "CRITICAL" ? "🚨 CRITICAL" : "⚠️ ALERT";
          const newToast: ToastAlert = {
            id: Math.random().toString(),
            message: `${toastEmoji}: ${event.type} attack detected from ${event.source_country} targeting ${event.destination_country}`,
            severity: event.severity
          };
          setToasts((prev) => [...prev.slice(-3), newToast]); // Limit to max 4 stacked toasts
          setTimeout(() => {
            setToasts((prev) => prev.filter((t) => t.id !== newToast.id));
          }, 4500);
        }

        // Tweak counters randomly to feel live
        setLiveStats((prev) => ({
          ...prev,
          totalThreats: prev.totalThreats + 1,
          attacksPerSecond: +(20 + Math.random() * 15).toFixed(1),
          successfulAttacks: prev.successfulAttacks + (Math.random() > 0.95 ? 1 : 0),
          blockedAttacks: prev.blockedAttacks + (Math.random() > 0.5 ? 1 : 0)
        }));
      }
    }, 1300);

    return () => clearInterval(streamInterval);
  }, [replayMode, threatDb]);

  // Handle Zoom and Pan functions
  const handleZoom = (direction: "in" | "out") => {
    setZoom((z) => Math.max(0.6, Math.min(8, direction === "in" ? z * 1.3 : z / 1.3)));
  };

  const handleResetMap = () => {
    setZoom(1.1);
    setPan({ x: -40, y: 15 });
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // Convert geoData features to projected SVG paths
  const mapPaths = useMemo(() => {
    if (!geoData) return [];
    return geoData.features.map((feature: any) => {
      const { type, coordinates } = feature.geometry;
      let pathString = "";

      const getPointsPath = (ring: number[][]) => {
        const pts = ring.map(([lon, lat]) => {
          const [px, py] = projectMiller(lon, lat);
          return `${px.toFixed(1)},${py.toFixed(1)}`;
        });
        return `M${pts.join(" L")}Z`;
      };

      if (type === "Polygon") {
        pathString = coordinates.map(getPointsPath).join(" ");
      } else if (type === "MultiPolygon") {
        pathString = coordinates.map((poly: any) => poly.map(getPointsPath).join(" ")).join(" ");
      }

      const rawId = String(feature.id || "");
      const normalizedId = (rawId === "-99" || !rawId) ? `${rawId}-${feature.properties.name}` : rawId;

      return {
        id: normalizedId,
        name: feature.properties.name,
        d: pathString
      };
    });
  }, [geoData]);

  // Aggregate threats count for countries to set threat levels
  const countryThreatAggregates = useMemo(() => {
    const counts: Record<string, { total: number; critical: number; high: number }> = {};
    threatDb.forEach((e) => {
      const code = e.destination_code;
      if (!counts[code]) counts[code] = { total: 0, critical: 0, high: 0 };
      counts[code].total++;
      if (e.severity === "CRITICAL") counts[code].critical++;
      if (e.severity === "HIGH") counts[code].high++;
    });
    return counts;
  }, [threatDb]);

  // Determine threat fill color for a country
  const getCountryFill = (id: string) => {
    const agg = countryThreatAggregates[id];
    if (!agg || agg.total === 0) return "#1976D2"; // Safe - Blue
    if (agg.critical > 8) return "#7f1d1d"; // Critical Attack - Dark Red
    if (agg.high > 15 || agg.critical > 2) return "#dc2626"; // Active Attack - Red
    return "#ea580c"; // Low Threat - Orange
  };

  // Filtered dataset for charts & tables
  const filteredThreats = useMemo(() => {
    let result = threatDb;

    if (filterSeverity !== "ALL") {
      result = result.filter((e) => e.severity === filterSeverity);
    }
    if (filterType !== "ALL") {
      result = result.filter((e) => e.type === filterType);
    }
    if (filterCountry !== "ALL") {
      result = result.filter((e) => e.destination_code === filterCountry || e.source_code === filterCountry);
    }
    if (filterOS !== "ALL") {
      result = result.filter((e) => e.os === filterOS);
    }
    if (filterIndustry !== "ALL") {
      result = result.filter((e) => e.industry === filterIndustry);
    }
    if (filterMalware !== "ALL") {
      result = result.filter((e) => e.malware_family === filterMalware);
    }
    if (filterVector !== "ALL") {
      result = result.filter((e) => e.attack_vector === filterVector);
    }
    if (filterDevice !== "ALL") {
      result = result.filter((e) => {
        if (filterDevice === "Server") return e.target_device.includes("Server") || e.target_device.includes("DB");
        if (filterDevice === "Cloud VM") return e.target_device.includes("VM");
        if (filterDevice === "Laptop") return e.target_device.includes("Laptop");
        if (filterDevice === "Firewall") return e.target_device.includes("Firewall");
        if (filterDevice === "Router") return e.target_device.includes("Switch");
        return true;
      });
    }

    if (searchQuery.trim() !== "") {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (e) =>
          e.id.toLowerCase().includes(q) ||
          e.ip.toLowerCase().includes(q) ||
          e.domain.toLowerCase().includes(q) ||
          e.exploit_used.toLowerCase().includes(q) ||
          e.source_country.toLowerCase().includes(q) ||
          e.destination_country.toLowerCase().includes(q) ||
          e.malware_family.toLowerCase().includes(q) ||
          e.target_device.toLowerCase().includes(q) ||
          e.os.toLowerCase().includes(q)
      );
    }

    return result;
  }, [threatDb, filterSeverity, filterType, filterCountry, filterOS, filterIndustry, filterMalware, filterVector, filterDevice, searchQuery]);

  // Selected Country data extraction
  const countryDetail = useMemo(() => {
    if (!selectedCountry) return null;
    const meta = COUNTRY_METADATA[selectedCountry];
    const name = meta?.name || selectedCountry;
    const flag = meta?.flag || "🏳️";

    const agg = countryThreatAggregates[selectedCountry];
    const activeCount = agg?.total || 0;
    const riskScore = agg ? Math.min(100, Math.round((agg.critical * 8 + agg.high * 3 + activeCount) / 1.5)) : 0;
    const threatLevel = riskScore > 75 ? "Critical" : riskScore > 40 ? "High" : riskScore > 10 ? "Medium" : "Low";

    return {
      code: selectedCountry,
      name,
      flag,
      activeCount,
      riskScore,
      threatLevel,
      securityStatus: riskScore > 75 ? "UNDER SEVERE ATTACK" : riskScore > 40 ? "HIGH ALERT" : "OPERATIONAL",
      infrastructure: riskScore > 75 ? "PARTIALLY COMPROMISED" : "NORMAL STABILITY",
      lastUpdated: new Date().toLocaleTimeString()
    };
  }, [selectedCountry, countryThreatAggregates]);

  // Detailed threat items filtered for selected country table
  const selectedCountryThreats = useMemo(() => {
    if (!selectedCountry) return [];
    return filteredThreats.filter((e) => e.destination_code === selectedCountry || e.source_code === selectedCountry);
  }, [selectedCountry, filteredThreats]);

  // Sort and Paginate country table
  const sortedSelectedThreats = useMemo(() => {
    const sorted = [...selectedCountryThreats];
    sorted.sort((a, b) => {
      let valA = a[tableSortColumn];
      let valB = b[tableSortColumn];

      if (typeof valA === "string") valA = valA.toLowerCase();
      if (typeof valB === "string") valB = valB.toLowerCase();

      if (valA < valB) return tableSortDir === "asc" ? -1 : 1;
      if (valA > valB) return tableSortDir === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [selectedCountryThreats, tableSortColumn, tableSortDir]);

  const paginatedThreats = useMemo(() => {
    const start = (tablePage - 1) * 8;
    return sortedSelectedThreats.slice(start, start + 8);
  }, [sortedSelectedThreats, tablePage]);

  // Total pages
  const totalTablePages = Math.ceil(sortedSelectedThreats.length / 8) || 1;

  const handleSort = (col: keyof ThreatEvent) => {
    if (tableSortColumn === col) {
      setTableSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setTableSortColumn(col);
      setTableSortDir("desc");
    }
    setTablePage(1);
  };

  // ECharts: Threats by Continent options
  const continentChartOption = useMemo(() => {
    const dist = { NorthAmerica: 0, Europe: 0, Asia: 0, SouthAmerica: 0, Australia: 0, Africa: 0 };
    filteredThreats.forEach((e) => {
      const c = e.destination_code;
      if (["USA", "CAN", "MEX"].includes(c)) dist.NorthAmerica++;
      else if (["DEU", "GBR", "FRA", "NLD", "POL", "SWE", "NOR", "FIN", "ITA", "ESP", "UKR"].includes(c)) dist.Europe++;
      else if (["CHN", "IND", "JPN", "KOR", "SGP", "IRN", "ISR", "SAU", "ARE", "TUR"].includes(c)) dist.Asia++;
      else if (["BRA", "ARG"].includes(c)) dist.SouthAmerica++;
      else if (["AUS"].includes(c)) dist.Australia++;
      else if (["ZAF", "EGY"].includes(c)) dist.Africa++;
    });

    return {
      tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
      legend: { bottom: "0", textStyle: { color: "#94a3b8", fontSize: 10 } },
      series: [
        {
          name: "Continents",
          type: "pie",
          radius: ["40%", "70%"],
          avoidLabelOverlap: false,
          itemStyle: { borderRadius: 6, borderColor: "#0f172a", borderWidth: 2 },
          label: { show: false },
          emphasis: { label: { show: true, fontSize: 12, fontWeight: "bold", color: "#f8fafc" } },
          data: [
            { value: dist.NorthAmerica, name: "N. America", itemStyle: { color: "#3b82f6" } },
            { value: dist.Europe, name: "Europe", itemStyle: { color: "#8b5cf6" } },
            { value: dist.Asia, name: "Asia", itemStyle: { color: "#ef4444" } },
            { value: dist.SouthAmerica, name: "S. America", itemStyle: { color: "#10b981" } },
            { value: dist.Australia, name: "Australia", itemStyle: { color: "#06b6d4" } },
            { value: dist.Africa, name: "Africa", itemStyle: { color: "#f97316" } }
          ]
        }
      ]
    };
  }, [filteredThreats]);

  // ECharts: Threats by Country (Horizontal Bar Chart)
  const countryChartOption = useMemo(() => {
    const targetMap: Record<string, number> = {};
    filteredThreats.forEach((e) => {
      const name = e.destination_country;
      targetMap[name] = (targetMap[name] || 0) + 1;
    });

    const sortedTargets = Object.entries(targetMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .reverse();

    return {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: "3%", right: "8%", bottom: "3%", top: "5%", containLabel: true },
      xAxis: {
        type: "value",
        splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.15)" } },
        axisLabel: { color: "#94a3b8", fontSize: 10 }
      },
      yAxis: {
        type: "category",
        data: sortedTargets.map((x) => x[0]),
        axisLabel: { color: "#94a3b8", fontSize: 10 }
      },
      series: [
        {
          name: "Threats Count",
          type: "bar",
          data: sortedTargets.map((x) => x[1]),
          itemStyle: {
            color: {
              type: "linear",
              x: 0, y: 0, x2: 1, y2: 0,
              colorStops: [
                { offset: 0, color: "rgba(6, 182, 212, 0.2)" },
                { offset: 1, color: "rgba(6, 182, 212, 0.85)" }
              ]
            },
            borderRadius: [0, 4, 4, 0]
          }
        }
      ]
    };
  }, [filteredThreats]);

  // ECharts: Threats by Attack Type (Radar Chart)
  const typeChartOption = useMemo(() => {
    const map: Record<string, number> = {};
    filteredThreats.forEach((e) => {
      map[e.type] = (map[e.type] || 0) + 1;
    });

    const indicators = ATTACK_TYPES.slice(0, 6).map((t) => ({ name: t, max: 150 }));
    const dataValues = ATTACK_TYPES.slice(0, 6).map((t) => map[t] || Math.floor(Math.random() * 40) + 15);

    return {
      tooltip: {},
      radar: {
        indicator: indicators,
        axisName: { color: "#94a3b8", fontSize: 9 },
        splitArea: { show: false },
        splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.25)" } }
      },
      series: [
        {
          name: "Threat vectors distribution",
          type: "radar",
          data: [
            {
              value: dataValues,
              name: "Threat Types",
              itemStyle: { color: "#8b5cf6" },
              areaStyle: { color: "rgba(139, 92, 246, 0.25)" }
            }
          ]
        }
      ]
    };
  }, [filteredThreats]);

  // ECharts: Threats Severity Timeline (Area Chart)
  const timelineChartOption = useMemo(() => {
    const timelineData = Array.from({ length: 12 }, (_, i) => `${14 - 12 + i + 1}:00`);

    return {
      tooltip: { trigger: "axis" },
      legend: { textStyle: { color: "#94a3b8" }, right: "5%" },
      grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: timelineData,
        axisLabel: { color: "#94a3b8" }
      },
      yAxis: {
        type: "value",
        splitLine: { lineStyle: { color: "rgba(51, 65, 85, 0.15)" } },
        axisLabel: { color: "#94a3b8" }
      },
      series: [
        {
          name: "Critical",
          type: "line",
          smooth: true,
          showSymbol: false,
          lineStyle: { color: "#ef4444", width: 2 },
          areaStyle: { color: "rgba(239, 68, 68, 0.1)" },
          data: [2, 5, 4, 8, 9, 14, 8, 12, 18, 15, 22, 29]
        },
        {
          name: "High",
          type: "line",
          smooth: true,
          showSymbol: false,
          lineStyle: { color: "#f97316", width: 2 },
          areaStyle: { color: "rgba(249, 115, 22, 0.07)" },
          data: [15, 22, 19, 32, 28, 45, 38, 52, 60, 58, 67, 85]
        }
      ]
    };
  }, []);

  return (
    <AppLayout title="SOC Threat Intelligence Dashboard">
      <div className="space-y-6 relative select-none">
        {/* Custom CSS keyframes */}
        <style dangerouslySetInnerHTML={{ __html: `
          @keyframes laser-flow {
            to {
              stroke-dashoffset: -20;
            }
          }
          @keyframes slide-up {
            from {
              transform: translateY(20px);
              opacity: 0;
            }
            to {
              transform: translateY(0);
              opacity: 1;
            }
          }
          @keyframes fade-in {
            from {
              opacity: 0;
            }
            to {
              transform: translateY(0);
              opacity: 1;
            }
          }
          .animate-laser-flow {
            animation: laser-flow 1.5s linear infinite;
          }
          .animate-slide-up {
            animation: slide-up 0.3s ease-out forwards;
          }
          .animate-fade-in {
            animation: fade-in 0.3s ease-out forwards;
          }
        ` }} />
        {/* Animated Cyber Canvas in Background */}
        <div className="absolute inset-0 -m-6 pointer-events-none overflow-hidden z-0">
          <canvas ref={canvasRef} className="w-full h-full opacity-60" />
        </div>

        {/* Real-time Toast Notifications Box (Bottom Right) */}
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 max-w-md w-full">
          {toasts.map((t) => (
            <div
              key={t.id}
              className={`p-3 rounded-lg border flex items-center gap-2 shadow-2xl transition duration-300 animate-slide-up backdrop-blur-md ${
                t.severity === "CRITICAL"
                  ? "bg-red-950/80 border-red-800 text-red-200"
                  : "bg-orange-950/80 border-orange-800 text-orange-200"
              }`}
            >
              <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400" />
              <span className="text-xs font-mono">{t.message}</span>
            </div>
          ))}
        </div>

        {/* Dashboard Header Banner */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 relative z-10">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <Globe className="w-8 h-8 text-cyan-400 animate-spin" style={{ animationDuration: "12s" }} />
              XDR Threat Intelligence Center
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Active global security posture analysis, real-time threat tracing, and MITRE ATT&CK framework vectors.
            </p>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setReplayMode(!replayMode)}
              className={`flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg border transition ${
                replayMode
                  ? "bg-cyan-500 text-slate-950 border-cyan-400 shadow-lg shadow-cyan-500/20"
                  : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
              }`}
            >
              {replayMode ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              {replayMode ? "LIVE FEED ACTIVE" : "PAUSED"}
            </button>
            <button
              onClick={handleResetMap}
              className="px-4 py-2 text-xs font-bold bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg flex items-center gap-1"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              RESET MAP
            </button>
          </div>
        </div>

        {/* 12 Cyber Intel Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-12 gap-3 relative z-10">
          {[
            { label: "Total Active Threats", val: liveStats.totalThreats.toLocaleString("en-US"), color: "text-red-400", bg: "border-red-900/50 bg-red-950/20 shadow-red-950/20" },
            { label: "Attacks / Sec", val: liveStats.attacksPerSecond, color: "text-amber-400", bg: "border-amber-900/50 bg-amber-950/20" },
            { label: "Countries Target", val: liveStats.countriesUnderAttack, color: "text-yellow-400", bg: "border-yellow-900/50 bg-yellow-950/20" },
            { label: "Active Botnets", val: liveStats.activeBotnets, color: "text-rose-400", bg: "border-rose-900/50 bg-rose-950/20" },
            { label: "Malware Detected", val: "3,410", color: "text-purple-400", bg: "border-purple-900/50 bg-purple-950/20" },
            { label: "Ransomware Campaigns", val: liveStats.malwareCampaigns, color: "text-red-400", bg: "border-red-900/50 bg-red-950/20" },
            { label: "Phishing URLs", val: "2,840", color: "text-orange-400", bg: "border-orange-900/50 bg-orange-950/20" },
            { label: "DDoS Wave Count", val: "1,280", color: "text-cyan-400", bg: "border-cyan-900/50 bg-cyan-950/20" },
            { label: "Zero-Day Exploits", val: "8", color: "text-pink-400", bg: "border-pink-900/50 bg-pink-950/20" },
            { label: "Critical Alerts", val: "114", color: "text-emerald-400", bg: "border-emerald-900/50 bg-emerald-950/20" },
            { label: "Blocked Attacks", val: liveStats.blockedAttacks.toLocaleString("en-US"), color: "text-cyan-400", bg: "border-cyan-900/50 bg-cyan-950/20" },
            { label: "Compromised Devices", val: liveStats.compromisedDevices.toLocaleString("en-US"), color: "text-rose-400", bg: "border-rose-900/50 bg-rose-950/20" }
          ].map((card, idx) => (
            <div key={idx} className={`lg:col-span-1 p-3 rounded-xl border ${card.bg} flex flex-col justify-between backdrop-blur-md shadow-2xl transition hover:-translate-y-0.5`}>
              <span className="text-[10px] font-bold tracking-wider uppercase text-slate-400 truncate">{card.label}</span>
              <span className={`text-xl font-extrabold mt-1.5 ${card.color}`}>{card.val}</span>
            </div>
          ))}
        </div>

        {/* Global Map & Sidebar Controls Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 relative z-10">
          {/* Filters Sidebar */}
          <div className="lg:col-span-1 bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-4 backdrop-blur-md shadow-2xl flex flex-col">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <span className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Filter className="w-4 h-4 text-cyan-400" />
                ADVANCED FILTERS
              </span>
              <span className="text-[10px] font-mono text-slate-500 uppercase">{filteredThreats.length} Matches</span>
            </div>

            <div className="space-y-3.5 flex-1">
              {/* Severity Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Threat Severity</label>
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL SEVERITIES</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              {/* Threat Type Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Attack Category</label>
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL ATTACK TYPES</option>
                  {ATTACK_TYPES.slice(0, 10).map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              {/* Targeted OS Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Target Operating System</label>
                <select
                  value={filterOS}
                  onChange={(e) => setFilterOS(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL OPERATING SYSTEMS</option>
                  <option value="Windows Server">Windows Server</option>
                  <option value="Linux">Linux</option>
                  <option value="macOS">macOS</option>
                  <option value="Android">Android</option>
                  <option value="Proprietary">Proprietary (Network)</option>
                </select>
              </div>

              {/* Target Device Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Device Class</label>
                <select
                  value={filterDevice}
                  onChange={(e) => setFilterDevice(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL DEVICE CLASSES</option>
                  <option value="Server">Servers</option>
                  <option value="Cloud VM">Cloud VMs</option>
                  <option value="Laptop">Laptops</option>
                  <option value="Firewall">Firewalls</option>
                  <option value="Router">Routers / Switches</option>
                </select>
              </div>

              {/* Target Industry Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Target Industry</label>
                <select
                  value={filterIndustry}
                  onChange={(e) => setFilterIndustry(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL INDUSTRIES</option>
                  {INDUSTRIES.map((ind) => (
                    <option key={ind} value={ind}>{ind}</option>
                  ))}
                </select>
              </div>

              {/* Malware Family Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Malware Family</label>
                <select
                  value={filterMalware}
                  onChange={(e) => setFilterMalware(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL FAMILIES</option>
                  {MALWARE_FAMILIES.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>

              {/* Attack Vector Dropdown */}
              <div>
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">Attack Vector</label>
                <select
                  value={filterVector}
                  onChange={(e) => setFilterVector(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL VECTORS</option>
                  {ATTACK_VECTORS.map((v) => (
                    <option key={v} value={v}>{v}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500 flex justify-between uppercase">
              <span>DB Feed Sync: Ok</span>
              <span>v1.2.4</span>
            </div>
          </div>

          {/* Interactive World Map Canvas */}
          <div className="lg:col-span-3 bg-slate-900/80 border border-slate-800 rounded-xl p-5 relative overflow-hidden backdrop-blur-md shadow-2xl flex flex-col justify-between">
            {/* Map Header details */}
            <div className="flex justify-between items-center mb-3">
              <span className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Globe className="w-5 h-5 text-red-500" />
                REAL-TIME THREAT ANATOMY MAP
              </span>
              
              <div className="flex items-center gap-3">
                {/* Floating controls inside container */}
                <div className="flex bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs text-slate-400 font-mono">
                  <button
                    onClick={() => setMapStyle("night")}
                    className={`px-2 py-1 rounded-md transition ${mapStyle === "night" ? "bg-cyan-950 text-cyan-400 font-bold" : "hover:text-slate-200"}`}
                  >
                    NIGHT MODE
                  </button>
                  <button
                    onClick={() => setMapStyle("satellite")}
                    className={`px-2 py-1 rounded-md transition ${mapStyle === "satellite" ? "bg-cyan-950 text-cyan-400 font-bold" : "hover:text-slate-200"}`}
                  >
                    SATELLITE STYLE
                  </button>
                </div>

                <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono">
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
                  LIVE STREAM
                </div>
              </div>
            </div>

            {/* Main Interactive Map Area */}
            <div
              ref={mapContainerRef}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              className="bg-[#050b14] border border-slate-800/80 rounded-xl h-[420px] relative overflow-hidden cursor-grab active:cursor-grabbing flex items-center justify-center"
              style={{ background: mapStyle === "night" ? "#061A40" : "#020710" }}
            >
              {/* Vector Cyber Grid Lines */}
              <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(25,118,210,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(25,118,210,0.06)_1px,transparent_1px)] bg-[size:3rem_3rem] pointer-events-none" />

              <svg
                width="100%"
                height="100%"
                viewBox="0 0 1000 500"
                className="w-full h-full select-none"
              >
                {/* Embedded Grid pattern definition */}
                <defs>
                  <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#061a40" stopOpacity="0.8" />
                    <stop offset="100%" stopColor="#020816" stopOpacity="1" />
                  </radialGradient>
                </defs>

                {/* Grid Overlay inside SVG */}
                <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                  {/* Render dynamic country paths */}
                  {mapPaths.map((country: { id: string; name: string; d: string }) => {
                    const fill = getCountryFill(country.id);
                    const isSelected = selectedCountry === country.id;

                    return (
                      <path
                        key={country.id}
                        d={country.d}
                        fill={fill}
                        stroke={isSelected ? "#00f2fe" : "rgba(148, 163, 184, 0.4)"}
                        strokeWidth={isSelected ? 1.5 : 0.4}
                        className="transition duration-200 hover:fill-opacity-80 hover:stroke-[#00f2fe] cursor-pointer"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCountry(country.id);
                          setTablePage(1);
                        }}
                      >
                        <title>{country.name}</title>
                      </path>
                    );
                  })}

                  {/* Realtime Laser Attack lines */}
                  {activeLasers.map((laser) => (
                    <g key={laser.id} className="pointer-events-none">
                      {/* Laser path */}
                      <path
                        d={`M ${laser.srcX} ${laser.srcY} Q ${(laser.srcX + laser.dstX) / 2} ${Math.min(laser.srcY, laser.dstY) - 60} ${laser.dstX} ${laser.dstY}`}
                        fill="none"
                        stroke={laser.color}
                        strokeWidth={2}
                        strokeDasharray="6 4"
                        strokeLinecap="round"
                        className="animate-laser-flow"
                      />
                      {/* Pulse rings at target */}
                      <circle cx={laser.dstX} cy={laser.dstY} r={6} fill={laser.color} opacity={0.8}>
                        <animate attributeName="r" values="6;28" dur="1s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.8;0" dur="1s" repeatCount="indefinite" />
                      </circle>
                      <circle cx={laser.dstX} cy={laser.dstY} r={4} fill={laser.color} />
                    </g>
                  ))}
                </g>
              </svg>

              {/* Floating Map Zoom / Reset UI controls */}
              <div className="absolute bottom-4 left-4 flex flex-col gap-1.5 z-20">
                <button
                  onClick={() => handleZoom("in")}
                  className="w-8 h-8 rounded-lg bg-slate-900/90 border border-slate-800 text-slate-300 font-bold hover:bg-slate-800 flex items-center justify-center shadow-lg"
                >
                  +
                </button>
                <button
                  onClick={() => handleZoom("out")}
                  className="w-8 h-8 rounded-lg bg-slate-900/90 border border-slate-800 text-slate-300 font-bold hover:bg-slate-800 flex items-center justify-center shadow-lg"
                >
                  -
                </button>
              </div>

              {/* Style controls (heatmap, cluster triggers) */}
              <div className="absolute bottom-4 right-4 flex gap-2 z-20">
                <button
                  onClick={() => setHeatmapEnabled(!heatmapEnabled)}
                  className={`px-3 py-1.5 text-[10px] font-bold rounded-lg border transition ${
                    heatmapEnabled ? "bg-red-500 text-white border-red-400" : "bg-slate-900/90 border-slate-800 text-slate-400"
                  }`}
                >
                  HEATMAP: {heatmapEnabled ? "ON" : "OFF"}
                </button>
                <button
                  onClick={() => setClusterView(!clusterView)}
                  className={`px-3 py-1.5 text-[10px] font-bold rounded-lg border transition ${
                    clusterView ? "bg-purple-500 text-white border-purple-400" : "bg-slate-900/90 border-slate-800 text-slate-400"
                  }`}
                >
                  CLUSTER VIEW: {clusterView ? "ON" : "OFF"}
                </button>
              </div>
            </div>

            {/* Time slider and replay controller */}
            <div className="mt-3.5 flex items-center gap-3.5 bg-slate-950/80 border border-slate-800 rounded-lg p-2.5">
              <span className="text-[10px] font-bold text-slate-400 font-mono">REPLAY SCANNER</span>
              <input
                type="range"
                min="0"
                max="100"
                value={timeProgress}
                onChange={(e) => setTimeProgress(Number(e.target.value))}
                className="flex-1 accent-cyan-500 bg-slate-800 h-1 rounded-lg cursor-pointer"
              />
              <span className="text-[10px] font-mono text-cyan-400">14:00 - 23:59</span>
            </div>
          </div>
        </div>

        {/* Selected Country Details Drawer (Slide-out modal) */}
        {selectedCountry && countryDetail && (
          <div className="bg-slate-900/95 border border-slate-850 rounded-xl p-6 relative z-30 shadow-2xl animate-fade-in space-y-6">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <span className="text-3xl">{countryDetail.flag}</span>
                <div>
                  <h2 className="text-xl font-black text-slate-100 uppercase tracking-wide">
                    {countryDetail.name} ({countryDetail.code})
                  </h2>
                  <p className="text-[10px] font-mono text-slate-400 uppercase mt-0.5">
                    Security status: <strong className="text-cyan-400">{countryDetail.securityStatus}</strong> • INFRASTRUCTURE: <strong className="text-cyan-400">{countryDetail.infrastructure}</strong>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedCountry(null)}
                className="p-1 rounded-lg bg-slate-850 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Widgets */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 flex flex-col justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Threat Level</span>
                <span className={`text-2xl font-black mt-2 ${countryDetail.riskScore > 75 ? "text-red-500" : "text-orange-400"}`}>
                  {countryDetail.threatLevel.toUpperCase()}
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 flex flex-col justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Risk Score Gauge</span>
                <span className="text-2xl font-black text-cyan-400 mt-2">{countryDetail.riskScore} / 100</span>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-850 flex flex-col justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Active Attacks Detected</span>
                <span className="text-2xl font-black text-slate-100 mt-2">{countryDetail.activeCount}</span>
              </div>

              {/* Sparkline trend area chart */}
              <div className="p-2 rounded-xl bg-slate-950 border border-slate-850 h-28 relative">
                <span className="text-[9px] font-bold text-slate-500 uppercase absolute top-2 left-2">Threat activity timeline (30 Days)</span>
                <ReactECharts option={getTrendOption(countryDetail.name)} style={{ height: "100%", width: "100%" }} />
              </div>
            </div>

            {/* Scrollable details table (handles 1000+ threats smoothly via paginating) */}
            <div className="space-y-4">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                <h3 className="text-sm font-bold text-slate-200">ACTIVE THREAT EVENT DATABASE ({sortedSelectedThreats.length} Events)</h3>

                {/* Filter and search parameters */}
                <div className="flex gap-2 w-full md:w-auto">
                  <input
                    type="text"
                    placeholder="Search country data..."
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setTablePage(1);
                    }}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none w-full md:w-60 focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-850 rounded-xl overflow-hidden shadow-2xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-900 border-b border-slate-850 text-[10px] font-bold text-slate-400 uppercase">
                        <th onClick={() => handleSort("id")} className="p-3 cursor-pointer hover:text-slate-200">Threat ID</th>
                        <th onClick={() => handleSort("type")} className="p-3 cursor-pointer hover:text-slate-200">Attack Type</th>
                        <th onClick={() => handleSort("severity")} className="p-3 cursor-pointer hover:text-slate-200">Severity</th>
                        <th onClick={() => handleSort("target_device")} className="p-3 cursor-pointer hover:text-slate-200">Target Host</th>
                        <th onClick={() => handleSort("os")} className="p-3 cursor-pointer hover:text-slate-200">OS</th>
                        <th onClick={() => handleSort("source_country")} className="p-3 cursor-pointer hover:text-slate-200">Source</th>
                        <th onClick={() => handleSort("ip")} className="p-3 cursor-pointer hover:text-slate-200">IP Address</th>
                        <th onClick={() => handleSort("cve_number")} className="p-3 cursor-pointer hover:text-slate-200">Exploit/CVE</th>
                        <th onClick={() => handleSort("attack_time")} className="p-3 cursor-pointer hover:text-slate-200">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850 font-mono">
                      {paginatedThreats.map((t) => (
                        <tr key={t.id} className="hover:bg-slate-900/40 transition">
                          <td className="p-3 text-cyan-400 font-bold">{t.id}</td>
                          <td className="p-3 text-slate-300 font-sans">{t.type}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[9px] font-black ${
                                t.severity === "CRITICAL"
                                  ? "bg-red-950/70 border border-red-800 text-red-400"
                                  : t.severity === "HIGH"
                                  ? "bg-orange-950/70 border border-orange-800 text-orange-400"
                                  : "bg-slate-800 text-slate-400"
                              }`}
                            >
                              {t.severity}
                            </span>
                          </td>
                          <td className="p-3 text-slate-400 font-sans">{t.target_device}</td>
                          <td className="p-3 text-slate-400">{t.os}</td>
                          <td className="p-3 text-slate-300 font-sans">{t.source_country}</td>
                          <td className="p-3 text-slate-400">{t.ip}</td>
                          <td className="p-3 text-slate-400">{t.cve_number}</td>
                          <td className="p-3 text-slate-400">{t.attack_time}</td>
                        </tr>
                      ))}
                      {paginatedThreats.length === 0 && (
                        <tr>
                          <td colSpan={9} className="p-6 text-center text-slate-500 font-sans">
                            No active threats matching current filters.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Table Pagination */}
                {totalTablePages > 1 && (
                  <div className="flex justify-between items-center p-3 bg-slate-900 border-t border-slate-850">
                    <span className="text-[10px] text-slate-400">
                      Showing page {tablePage} of {totalTablePages} ({sortedSelectedThreats.length} total events)
                    </span>
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => setTablePage((p) => Math.max(1, p - 1))}
                        disabled={tablePage === 1}
                        className="p-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition disabled:opacity-30"
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setTablePage((p) => Math.min(totalTablePages, p + 1))}
                        disabled={tablePage === totalTablePages}
                        className="p-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition disabled:opacity-30"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Global Search and Platform Correlation Widget */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 backdrop-blur-md shadow-2xl relative z-10">
          <h2 className="text-md font-bold text-slate-200 flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400 animate-pulse" />
            SOC PLATFORM THREAT SEARCH & CORRELATION
          </h2>

          <div className="flex gap-2">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search across 1,050+ threat events by Domain, URL, IP, CVE, Malware Name, Device OS..."
              className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-xs text-slate-200 outline-none focus:border-cyan-500 font-mono"
            />
            <button
              onClick={() => {
                if (searchQuery.trim()) {
                  // Focus search and scroll to detail table if open, or select USA by default to demo
                  if (!selectedCountry) setSelectedCountry("USA");
                }
              }}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-lg transition text-xs flex items-center gap-2"
            >
              <Link2 className="w-4 h-4" />
              QUERY THREAT IOC
            </button>
          </div>
        </div>

        {/* Analytics Section - Charts Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
          {/* Threats by Continent */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 backdrop-blur-md shadow-2xl flex flex-col justify-between h-72">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              THREATS BY CONTINENT
            </span>
            <div className="flex-1 min-h-0 pt-3">
              <ReactECharts option={continentChartOption} style={{ height: "100%", width: "100%" }} />
            </div>
          </div>

          {/* Threats by Country */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 backdrop-blur-md shadow-2xl flex flex-col justify-between h-72">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
              <Activity className="w-4 h-4 text-red-400" />
              TOP TARGETED COUNTRIES
            </span>
            <div className="flex-1 min-h-0 pt-3">
              <ReactECharts option={countryChartOption} style={{ height: "100%", width: "100%" }} />
            </div>
          </div>

          {/* Threats by Attack Type */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 backdrop-blur-md shadow-2xl flex flex-col justify-between h-72">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              THREAT VECTOR RADAR
            </span>
            <div className="flex-1 min-h-0 pt-3">
              <ReactECharts option={typeChartOption} style={{ height: "100%", width: "100%" }} />
            </div>
          </div>

          {/* Severity Timeline */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 backdrop-blur-md shadow-2xl flex flex-col justify-between h-72">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
              <Clock className="w-4 h-4 text-amber-400" />
              12-HOUR SEVERITY TIMELINE
            </span>
            <div className="flex-1 min-h-0 pt-3">
              <ReactECharts option={timelineChartOption} style={{ height: "100%", width: "100%" }} />
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Coverage Widget */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md shadow-2xl relative z-10 space-y-4">
          <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
            <Server className="w-4 h-4 text-cyan-400" />
            MITRE ATT&CK MATRIX INTRUSION COVERAGE
          </span>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
            {[
              { tactic: "Initial Access", techs: ["Phishing (T1566)", "Exploit Public (T1190)"], score: 92 },
              { tactic: "Execution", techs: ["User Execution (T1204)", "Command Line (T1059)"], score: 85 },
              { tactic: "Persistence", techs: ["Registry Run Keys (T1547)", "Create Process (T1543)"], score: 74 },
              { tactic: "Credential Access", techs: ["OS Credential Dumping (T1003)", "Brute Force (T1110)"], score: 68 },
              { tactic: "Lateral Movement", techs: ["Remote Services (T1021)", "WMI Execution (T1047)"], score: 80 },
              { tactic: "Exfiltration", techs: ["Exfil Over C2 Channel (T1041)", "Data Encrypted (T1486)"], score: 94 }
            ].map((col, idx) => (
              <div key={idx} className="p-3 bg-slate-950 border border-slate-850 rounded-lg flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex justify-between items-center">
                    <strong className="text-[10px] font-bold text-slate-300 uppercase tracking-wide">{col.tactic}</strong>
                    <span className="text-[9px] font-mono text-cyan-400 font-black">{col.score}%</span>
                  </div>
                  <div className="mt-2 space-y-1.5">
                    {col.techs.map((tech, tIdx) => (
                      <span key={tIdx} className="block text-[10px] font-mono text-slate-400 bg-slate-900 p-1 rounded border border-slate-850">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full" style={{ width: `${col.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Attack Timeline Event Log */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 backdrop-blur-md shadow-2xl relative z-10 space-y-4">
          <span className="text-xs font-bold text-slate-200 flex items-center gap-2 border-b border-slate-850 pb-2">
            <Flame className="w-4 h-4 text-orange-400 animate-pulse" />
            CHRONOLOGICAL SOC SECURITY TIMELINE LOG
          </span>

          <div className="max-h-60 overflow-y-auto space-y-2 pr-1 scrollbar-thin">
            {threatDb.slice(0, 15).map((evt, idx) => (
              <div
                key={evt.id}
                className={`p-3 bg-slate-950 border rounded-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-2.5 transition hover:border-slate-800 ${
                  evt.severity === "CRITICAL"
                    ? "border-red-950 bg-red-950/5"
                    : evt.severity === "HIGH"
                    ? "border-orange-950 bg-orange-950/5"
                    : "border-slate-850"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-500">{evt.attack_time}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[9px] font-black ${
                      evt.severity === "CRITICAL"
                        ? "bg-red-950 border border-red-800 text-red-400 animate-pulse"
                        : evt.severity === "HIGH"
                        ? "bg-orange-950 border border-orange-800 text-orange-400"
                        : "bg-slate-850 text-slate-400"
                    }`}
                  >
                    {evt.severity}
                  </span>
                  <div className="text-xs font-sans">
                    <strong className="text-slate-200 font-black">{evt.type}</strong> target in{" "}
                    <strong className="text-slate-300">{evt.destination_country}</strong> via host{" "}
                    <span className="text-cyan-400 font-mono text-[10px] bg-slate-900 border border-slate-800 px-1 py-0.5 rounded">
                      {evt.target_device}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
                  <span>VECTOR: <strong className="text-slate-400">{evt.attack_vector}</strong></span>
                  <span>IP: <strong className="text-slate-400">{evt.ip}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Supported Attack Types List footer */}
        <div className="bg-slate-950 border border-slate-850 rounded-xl p-4 text-center text-xs text-slate-400 relative z-10 font-mono uppercase tracking-wider">
          <span>Supported Scan Vectors: Ransomware • DDoS • Phishing • Credential Stuffing • Brute Force • SQL Injection • XSS • Zero-Day • Remote Code Execution • Malware • APT • Cryptojacking</span>
        </div>
      </div>
    </AppLayout>
  );
}

// Sparkline configuration options for Country Details Chart
function getTrendOption(countryName: string) {
  const points = Array.from({ length: 30 }, (_, i) => Math.floor(Math.random() * 32) + 12);
  return {
    grid: { left: 0, right: 0, top: 4, bottom: 4 },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: Array.from({ length: 30 }, (_, i) => `Day ${i + 1}`),
      show: false
    },
    yAxis: {
      type: "value",
      show: false
    },
    series: [
      {
        name: "Threats",
        type: "line",
        smooth: true,
        symbol: "none",
        data: points,
        lineStyle: { color: "#06b6d4", width: 1.5 },
        areaStyle: {
          color: {
            type: "linear",
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: "rgba(6, 182, 212, 0.3)" },
              { offset: 1, color: "rgba(6, 182, 212, 0)" }
            ]
          }
        }
      }
    ]
  };
}
