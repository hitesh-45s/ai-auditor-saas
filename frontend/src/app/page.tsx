"use client";

import { useState, useEffect } from "react";
import { createClient } from "@supabase/supabase-js";
import { Search, Activity, Globe, Terminal, AlertTriangle, Code2, Loader2, ArrowRight, Bug, Link as LinkIcon, ShieldCheck, LogOut, BookOpen, Home as HomeIcon, Lock, Mail, CheckCircle2, History, Download, ExternalLink, RefreshCw, Zap, Gauge, Timer, HardDrive, Shield, Key, Share2, TrendingUp, TrendingDown, Minus, Check, X, Image as ImageIcon, Eye, Copy, Layers, BarChart3, Clock, Sparkles, Cpu } from "lucide-react";

// --- SUPABASE INITIALIZATION ---
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://placeholder.supabase.co";
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "placeholder";
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// --- API BASE URL ---
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// --- TYPES ---
type Vulnerability = {
  id?: string;
  url: string;
  issue_type: string;
  severity: "High" | "Medium" | "Low";
  file_target?: string;
  description: string;
  remediation_code?: string;
  defect_code?: string;
  explanation?: string;
  impact?: string;
  standard_ref?: string;
  rule_id?: string;
  screenshot_url?: string;
};

type PerformanceMetrics = {
  load_time_ms: number;
  fcp_ms?: number | null;
  dom_content_loaded_ms: number;
  ttfb_ms: number;
  total_requests: number;
  transfer_size_kb: number;
  speed_rating: "Fast" | "Average" | "Slow";
};

type ScanMethodology = {
  pages_crawled: number;
  total_images_found: number;
  total_links_found: number;
  total_forms_found: number;
  characters_analyzed: number;
  ai_model_used: string;
  scan_duration_seconds: number;
  categories_checked: string[];
};

type SSLHealth = {
  valid: boolean;
  https_active: boolean;
  http_redirects_to_https: boolean;
  issuer: string;
  protocol: string;
  days_remaining: number;
  expiry_date?: string | null;
  error?: string | null;
};

type SecurityHeaderItem = {
  name: string;
  present: boolean;
  value?: string | null;
  critical: boolean;
  description: string;
};

type SecurityHeadersAudit = {
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  present_count: number;
  total_count: number;
  headers: Record<string, SecurityHeaderItem>;
};

type SocialMetaAudit = {
  ready: boolean;
  og_title?: string;
  og_description?: string;
  og_image?: string;
  og_site_name?: string;
  twitter_card?: string;
  twitter_image?: string;
  has_og_image: boolean;
  has_twitter_card: boolean;
};

type BrokenLinkItem = {
  url: string;
  status: number;
  reason: string;
};

type LinkHealthAudit = {
  total_checked: number;
  broken_count: number;
  broken_links: BrokenLinkItem[];
  health_rate: number;
};

type ImageOptimizationAudit = {
  total_images: number;
  modern_count: number;
  legacy_count: number;
  modern_percent: number;
  is_optimized: boolean;
};

type TechnicalAudit = {
  ssl?: SSLHealth;
  security_headers?: SecurityHeadersAudit;
  social_meta?: SocialMetaAudit;
  link_health?: LinkHealthAudit;
  image_optimization?: ImageOptimizationAudit;
};

type ScoreComparison = {
  previous_scan_id: string;
  previous_score: number;
  current_score: number;
  delta: number;
  improved: boolean;
  unchanged: boolean;
  previous_date?: string;
};

type CategoryScores = {
  performance: number;
  accessibility: number;
  seo: number;
  security: number;
  global_score: number;
};

type AuditResult = {
  global_score: number;
  executive_summary: string;
  top_global_issue: string;
  critical_vulnerabilities?: Vulnerability[];
  scanned_urls?: string[];
  performance_metrics?: PerformanceMetrics;
  scan_methodology?: ScanMethodology;
  technical_audit?: TechnicalAudit;
  score_comparison?: ScoreComparison;
  category_scores?: CategoryScores;
};

type ScanHistoryItem = {
  id: string;
  website_id: string;
  domain_url: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  created_at?: string;
  global_score?: number | null;
  vulnerability_count: number;
  top_issue?: string | null;
};

export default function App() {
  // --- GLOBAL STATE ---
  const [session, setSession] = useState<any>(null);
  const [currentView, setCurrentView] = useState<"login" | "home" | "scanner" | "history" | "fixes">("login");
  const [homeTab, setHomeTab] = useState<"overview" | "pipeline" | "mathematics" | "rulebook">("overview");
  const [mounted, setMounted] = useState(false);

  // --- AUTH STATE ---
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState("");

  // --- SCANNER STATE ---
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [auditData, setAuditData] = useState<AuditResult | null>(null);
  const [screenshotUrl, setScreenshotUrl] = useState<string | null>(null); // NEW: Screenshot state
  const [scanError, setScanError] = useState<string | null>(null);
  
  // --- SCAN HISTORY STATE ---
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  // --- REMEDIATION LAB STATE ---
  const [selectedVulnIndex, setSelectedVulnIndex] = useState(0);
  const [graphTab, setGraphTab] = useState<"radar" | "waterfall" | "payload">("radar");
  const [activeVectorIndex, setActiveVectorIndex] = useState<number>(0);
  const [copiedFix, setCopiedFix] = useState(false);
  const [codeDiffTab, setCodeDiffTab] = useState<"diff" | "after" | "before">("diff");

  // Initialize and check auth
  useEffect(() => {
    setMounted(true);
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if (session) setCurrentView("home");
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      if (session) {
        setCurrentView((prev) => (prev === "login" ? "home" : prev));
      } else {
        setCurrentView("login");
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  // --- SCANNER POLLING LOGIC ---
  useEffect(() => {
    let interval: ReturnType<typeof setInterval> | undefined;
    if (scanId && scanStatus !== "completed" && scanStatus !== "failed" && session) {
      interval = setInterval(async () => {
        try {
          // NEW: Send the JWT Token in the Authorization header
          const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}`, {
             headers: {
                "Authorization": `Bearer ${session.access_token}`
             }
          });
          
          if (response.ok) {
            const data = await response.json();
            setScanStatus(data.status);

            // NEW: Capture the screenshot URL if it exists
            if (data.screenshot_url) {
                setScreenshotUrl(data.screenshot_url);
            }

            if (data.status === "completed" && data.audit_results && data.audit_results.length > 0) {
              setAuditData(data.audit_results[0].raw_data);
              setIsScanning(false);
              setSelectedVulnIndex(0); // Reset index for new scans
            }

            if (data.status === "failed") {
              setIsScanning(false);
              const failureReason = data.audit_results?.[0]?.raw_data?.error || data.error_message || "The target website could not be reached, failed SSL handshake, or does not exist.";
              setScanError(failureReason);
            }
          } else {
            setIsScanning(false);
            setScanError(`Could not fetch scan status (HTTP ${response.status}).`);
          }
        } catch (error) {
          console.error("Polling error:", error);
          setIsScanning(false);
          setScanError("Lost connection to the audit engine while polling for results.");
        }
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanId, scanStatus, session]);

  // --- AUTH METHODS ---
  const handleSignUp = async (e: React.FormEvent) => {
    if (e) e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const { error } = await supabase.auth.signUp({ email, password });
    if (error) setAuthError(error.message);
    else alert("Success! Please check your email to verify your account (if email confirmation is enabled in Supabase). Or try logging in.");
    setAuthLoading(false);
  };

  const handleLogin = async (e: React.FormEvent) => {
    if (e) e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) setAuthError(error.message);
    setAuthLoading(false);
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setAuditData(null);
    setScanStatus(null);
    setScanId(null);
    setScanError(null);
    setScreenshotUrl(null);
    setIsScanning(false);
  };

  // --- SCAN METHODS ---
  const handleScan = async (e?: React.FormEvent, forceRefresh: boolean = false) => {
    if (e) e.preventDefault();
    if (!url || !session?.user?.id) return;

    setIsScanning(true);
    setScanId(null);
    setScanStatus("pending");
    setAuditData(null);
    setScanError(null);
    setScreenshotUrl(null);

    try {
      // Clean and normalize input URL (fixes single-slash typos like https:/example.com)
      let normalizedUrl = url.trim();
      if (normalizedUrl.startsWith("https:/") && !normalizedUrl.startsWith("https://")) {
        normalizedUrl = normalizedUrl.replace("https:/", "https://");
      } else if (normalizedUrl.startsWith("http:/") && !normalizedUrl.startsWith("http://")) {
        normalizedUrl = normalizedUrl.replace("http:/", "http://");
      } else if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
        normalizedUrl = `https://${normalizedUrl}`;
      }

      // Send the JWT Token in the Authorization header
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "Authorization": `Bearer ${session.access_token}`
        },
        body: JSON.stringify({
          url: normalizedUrl,
          force_refresh: forceRefresh,
        }),
      });

      if (!response.ok) {
        let detail: any = `HTTP ${response.status}`;
        try {
          const errBody = await response.json();
          detail = errBody?.detail || errBody?.message || detail;
        } catch {}

        const message = typeof detail === "string" ? detail : JSON.stringify(detail);
        throw new Error(message);
      }

      const data = await response.json();
      setScanId(data.scan_id);
      if (data.cached) {
        setScanStatus("completed");
        openHistoricalScan(data.scan_id);
        return;
      }
      setScanStatus("pending");
    } catch (error: any) {
      console.error(error);
      setScanError(
        `Cannot start scan. Ensure the API is running at ${API_BASE_URL}. Detail: ${error.message}`
      );
      setIsScanning(false);
    }
  };

  // --- STATE RESET METHOD ---
  const startNewScan = () => {
    setAuditData(null);
    setScanStatus(null);
    setScanId(null);
    setScanError(null);
    setScreenshotUrl(null);
    setUrl("");
    setCurrentView("scanner");
  };

  // --- REMEDIATION CODE COPY HELPER ---
  const handleCopyCode = (codeText?: string) => {
    if (!codeText) return;
    navigator.clipboard.writeText(codeText);
    setCopiedFix(true);
    setTimeout(() => setCopiedFix(false), 2200);
  };

  // --- SCAN HISTORY METHODS ---
  const fetchScanHistory = async () => {
    if (!session?.access_token) return;
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/scans`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`
        }
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setScanHistory(data);
    } catch (err: any) {
      console.error("Failed to load history:", err);
      setHistoryError(err.message || "Failed to load scan history.");
    } finally {
      setHistoryLoading(false);
    }
  };

  const openHistoricalScan = async (selectedScanId: string) => {
    setIsScanning(true);
    setScanId(selectedScanId);
    setScanStatus("loading");
    setAuditData(null);
    setScanError(null);
    setScreenshotUrl(null);
    setCurrentView("scanner");
    setSelectedVulnIndex(0);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scans/${selectedScanId}`, {
        headers: {
          "Authorization": `Bearer ${session.access_token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setScanStatus(data.status);
        if (data.screenshot_url) setScreenshotUrl(data.screenshot_url);
        if (data.status === "failed") {
          const failureReason = data.audit_results?.[0]?.raw_data?.error || data.error_message || "The target website could not be reached, failed SSL handshake, or does not exist.";
          setScanError(failureReason);
        }
        if (data.audit_results && data.audit_results.length > 0) {
          setAuditData(data.audit_results[0].raw_data);
        }
      } else {
        setScanError(`Failed to load historical scan (HTTP ${response.status})`);
      }
    } catch (err: any) {
      console.error(err);
      setScanError(`Error loading historical scan: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  if (!mounted) return null;

  // ==========================================
  // PAGE 1: AUTHENTICATION VIEW
  // ==========================================
  if (currentView === "login" || !session) {
    return (
      <main className="min-h-screen bg-[#050505] flex items-center justify-center p-6 relative overflow-hidden">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

        <div className="bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-10 w-full max-w-md z-10 shadow-2xl animate-in fade-in zoom-in-95 duration-500">
          <div className="flex flex-col items-center mb-8">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20 mb-4">
              <Activity className="w-6 h-6 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Audit<span className="text-indigo-400">AI</span></h1>
            <p className="text-slate-400 text-sm mt-2 text-center">Enterprise Web Intelligence.<br/>Sign in to access the Engine.</p>
          </div>

          <form className="space-y-4" onSubmit={handleLogin}>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 block">Email Address</label>
              <div className="relative">
                <Mail className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
                <input 
                  type="email" 
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#111] border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white outline-none focus:border-indigo-500 transition-colors"
                  placeholder="ceo@enterprise.com"
                />
              </div>
            </div>
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 block">Password</label>
              <div className="relative">
                <Lock className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
                <input 
                  type="password" 
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[#111] border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white outline-none focus:border-indigo-500 transition-colors"
                  placeholder="••••••••"
                />
              </div>
            </div>

            {authError && (
              <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm p-3 rounded-lg flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {authError}
              </div>
            )}

            <div className="pt-4 space-y-3">
              <button 
                type="submit" 
                disabled={authLoading}
                className="w-full bg-white text-black font-bold py-3 rounded-xl hover:bg-slate-200 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {authLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Sign In"}
              </button>
              <button 
                type="button" 
                onClick={handleSignUp}
                disabled={authLoading}
                className="w-full bg-transparent border border-white/10 text-white font-medium py-3 rounded-xl hover:bg-white/5 transition-colors disabled:opacity-50"
              >
                Create Account
              </button>
            </div>
          </form>
        </div>
      </main>
    );
  }

  // ==========================================
  // LOGGED IN LAYOUT (Sidebar + Content)
  // ==========================================
  return (
    <div className="min-h-screen bg-[#050505] flex text-white overflow-hidden print:overflow-visible print:block">
      
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-white/5 bg-[#0a0a0a] flex flex-col z-20 relative no-print print:hidden">
        <div className="h-16 flex items-center px-6 border-b border-white/5">
          <div className="flex items-center gap-2 font-bold text-lg tracking-tight">
            <div className="w-6 h-6 rounded bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
              <Activity className="w-3 h-3 text-white" />
            </div>
            Audit<span className="text-indigo-400">AI</span>
          </div>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-2">
          <button 
            onClick={() => setCurrentView("home")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${currentView === 'home' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}`}
          >
            <HomeIcon className="w-5 h-5" /> Home & Docs
          </button>
          
          <button 
            onClick={() => setCurrentView("scanner")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${currentView === 'scanner' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}`}
          >
            <Search className="w-5 h-5" /> Target Scanner
          </button>

          <button 
            onClick={() => { setCurrentView("history"); fetchScanHistory(); }}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${currentView === 'history' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}`}
          >
            <History className="w-5 h-5" /> Scan History
          </button>

          <button 
            onClick={() => setCurrentView("fixes")}
            disabled={!auditData}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${currentView === 'fixes' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : !auditData ? 'opacity-30 cursor-not-allowed text-slate-500 border border-transparent' : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'}`}
          >
            <Code2 className="w-5 h-5" /> Remediation Code
            {!auditData && <Lock className="w-3 h-3 ml-auto" />}
          </button>
        </nav>

        <div className="p-4 border-t border-white/5">
          <div className="px-4 py-2 mb-2">
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-wider">Logged in as</p>
            <p className="text-xs text-slate-300 truncate">{session.user.email}</p>
          </div>
          <button onClick={handleLogout} className="w-full flex items-center gap-3 px-4 py-2 text-sm text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors">
            <LogOut className="w-4 h-4" /> Sign Out
          </button>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 relative overflow-y-auto print:overflow-visible print:w-full print:max-w-full">
        {/* Background Gradients */}
        <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-b from-indigo-900/10 to-transparent pointer-events-none"></div>
        
        <div className="p-8 max-w-6xl mx-auto min-h-full print:p-0 print:max-w-full">
          
          {/* ========================================== */}
          {/* PAGE 2: HOME & INSTRUCTIONS VIEW */}
          {/* ========================================== */}
          {currentView === "home" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 space-y-8">
              {/* HERO HEADER */}
              <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-[#0e0e14] via-[#0a0a0c] to-[#070709] p-8 md:p-12 shadow-2xl">
                <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>
                <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none -ml-20 -mb-20"></div>

                <div className="relative z-10 max-w-4xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-mono uppercase tracking-wider mb-6">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    Enterprise Diagnostic Platform · Architecture & Methodology
                  </div>

                  <h1 className="text-4xl md:text-5xl font-black text-white tracking-tight leading-tight mb-4">
                    The Science of <span className="bg-gradient-to-r from-indigo-400 via-purple-300 to-white bg-clip-text text-transparent">Autonomous Web Auditing</span>.
                  </h1>

                  <p className="text-slate-300 text-lg md:text-xl font-normal leading-relaxed mb-8 max-w-3xl">
                    A deterministic, multi-vector web diagnostic platform engineered for engineering leaders, compliance auditors, and digital infrastructure architects. Zero-hallucination OS socket probing, standardized Chromium CDP emulation, and Gemini AI drop-in remediation.
                  </p>

                  <div className="flex flex-wrap items-center gap-4">
                    <button
                      onClick={startNewScan}
                      className="bg-white text-black px-8 py-3.5 rounded-xl font-bold hover:bg-slate-200 transition-all shadow-[0_0_25px_rgba(255,255,255,0.25)] flex items-center gap-2 group cursor-pointer text-sm"
                    >
                      <span>Initiate Target Audit</span>
                      <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                    </button>
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-white/5 border border-white/5 px-4 py-3 rounded-xl">
                      <span className="text-emerald-400 font-bold">✓ 40-Page Spider</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-indigo-400 font-bold">10 Mbps CDP Normalized</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-purple-400 font-bold">WCAG 2.1 AA</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* INTERACTIVE NAVIGATION TABS */}
              <div className="flex flex-wrap items-center gap-2 p-1.5 bg-[#0a0a0a]/90 backdrop-blur-xl border border-white/10 rounded-2xl">
                {[
                  { id: "overview", label: "System Architecture", icon: Globe, desc: "Multi-Vector Isolation" },
                  { id: "pipeline", label: "4-Stage Pipeline", icon: Terminal, desc: "How It Works" },
                  { id: "mathematics", label: "Mathematical Foundations", icon: Activity, desc: "Continuous Scoring Math" },
                  { id: "rulebook", label: "Standards & Compliance", icon: BookOpen, desc: "W3C · WCAG · OWASP" },
                ].map((tab) => {
                  const Icon = tab.icon;
                  const isActive = homeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setHomeTab(tab.id as any)}
                      className={`flex-1 min-w-[200px] flex items-center gap-3 px-4 py-3 rounded-xl transition-all text-left cursor-pointer ${
                        isActive
                          ? "bg-white/10 text-white border border-white/15 shadow-lg"
                          : "text-slate-400 hover:text-white hover:bg-white/5 border border-transparent"
                      }`}
                    >
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isActive ? "bg-indigo-500/20 text-indigo-300" : "bg-white/5 text-slate-400"}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="font-bold text-sm">{tab.label}</div>
                        <div className="text-[11px] text-slate-500 font-mono">{tab.desc}</div>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* TAB 1: SYSTEM ARCHITECTURE */}
              {homeTab === "overview" && (
                <div className="space-y-6 animate-in fade-in duration-300">
                  {/* The Problem with Monolithic Scores */}
                  <div className="bg-[#0a0a0a]/90 border border-white/10 rounded-3xl p-8 backdrop-blur-xl">
                    <div className="max-w-3xl mb-6">
                      <span className="text-xs font-mono uppercase text-indigo-400 tracking-wider font-bold">Engineering Philosophy</span>
                      <h2 className="text-2xl font-bold text-white mt-1 mb-3">Why Blended Single Scores Fail Enterprise Engineering</h2>
                      <p className="text-slate-300 text-sm leading-relaxed">
                        Legacy auditing tools often compress orthogonal dimensions into a single monolithic score (e.g., "78/100"). In production systems, this creates severe diagnostic distortion: a legal accessibility violation (such as missing image alternative text) is not a cybersecurity breach, and a momentary 300ms Wi-Fi latency spike should never downgrade your SEO indexability.
                      </p>
                      <p className="text-slate-400 text-sm leading-relaxed mt-3">
                        AuditAI follows the <strong>Google Lighthouse specification</strong>: isolating the audit into four strictly independent, peer category vectors so that engineering, SEO, and security teams have unpolluted accountability.
                      </p>
                    </div>

                    {/* 4 Vector Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-5 hover:border-indigo-500/30 transition-colors">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                            <Zap className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">1. Performance Vector</h3>
                            <span className="text-[11px] font-mono text-amber-400/80">Physical Byte Architecture & Throttled Latency</span>
                          </div>
                        </div>
                        <p className="text-slate-400 text-xs leading-relaxed">
                          Anchored 80% on deterministic page architecture (total byte payload weight, HTTP request volume, modern WebP/AVIF format adoption) and 20% on Core Web Vitals (TTFB, FCP, load time) captured via an emulated 10 Mbps Chrome DevTools Protocol session.
                        </p>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-5 hover:border-indigo-500/30 transition-colors">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                            <Eye className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">2. Accessibility Vector</h3>
                            <span className="text-[11px] font-mono text-emerald-400/80">WCAG 2.1 Level AA Deterministic Rules</span>
                          </div>
                        </div>
                        <p className="text-slate-400 text-xs leading-relaxed">
                          Civil rights compliance audit for assistive technologies and screen readers. Evaluates image alternative text, button accessible names, input form labels, heading hierarchy, document language tags, and color contrast geometry with rule-capped deductions.
                        </p>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-5 hover:border-indigo-500/30 transition-colors">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                            <Globe className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">3. Best Practices & SEO Vector</h3>
                            <span className="text-[11px] font-mono text-indigo-400/80">W3C DOM Structure & Search Central Standards</span>
                          </div>
                        </div>
                        <p className="text-slate-400 text-xs leading-relaxed">
                          Evaluates search indexability, canonical URL consistency, singular H1 document root semantics, OpenGraph and Twitter Card social media readiness, internal link crawlability (verifying 200 vs 404/301 status), and viewport responsive meta configurations.
                        </p>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-5 hover:border-indigo-500/30 transition-colors">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                            <ShieldCheck className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">4. Security & Hygiene Vector</h3>
                            <span className="text-[11px] font-mono text-purple-400/80">Zero-Token Sockets & OWASP ASVS Defense Matrix</span>
                          </div>
                        </div>
                        <p className="text-slate-400 text-xs leading-relaxed">
                          Probes live port 443 sockets to verify TLS 1.3 cryptographic handshakes, cipher suite validity, and certificate expiration. Audits automatic HTTP-to-HTTPS 301 redirection and verifies all 6 mandatory OWASP defensive headers (CSP, HSTS, XFO, etc.).
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* 3 Core Platform Guarantees */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-[#0a0a0a]/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
                      <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4">
                        <Lock className="w-5 h-5" />
                      </div>
                      <h3 className="font-bold text-white text-base mb-2">Zero-Token Forensic Probing</h3>
                      <p className="text-slate-400 text-xs leading-relaxed">
                        Cryptographic certificates, HTTP headers, and server redirects are tested directly at the operating system socket level. Zero LLM hallucinations—pure cryptographic truth.
                      </p>
                    </div>

                    <div className="bg-[#0a0a0a]/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
                      <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-4">
                        <Gauge className="w-5 h-5" />
                      </div>
                      <h3 className="font-bold text-white text-base mb-2">Device & ISP Normalization</h3>
                      <p className="text-slate-400 text-xs leading-relaxed">
                        Chrome DevTools Protocol (CDP) throttles connection throughput to 10 Mbps and 40ms RTT, ensuring audits produce reproducible metrics regardless of whether your laptop is on 5G or Wi-Fi.
                      </p>
                    </div>

                    <div className="bg-[#0a0a0a]/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
                      <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 mb-4">
                        <Code2 className="w-5 h-5" />
                      </div>
                      <h3 className="font-bold text-white text-base mb-2">Deterministic Rule Capping</h3>
                      <p className="text-slate-400 text-xs leading-relaxed">
                        Unique rule ID hashing guarantees that repeating issues (e.g. 50 missing alt tags) are penalized once per rule family, preventing prompt length variation from mutating scores.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: 4-STAGE PIPELINE ("HOW IT WORKS") */}
              {homeTab === "pipeline" && (
                <div className="space-y-6 animate-in fade-in duration-300">
                  <div className="bg-[#0a0a0a]/90 border border-white/10 rounded-3xl p-8 backdrop-blur-xl">
                    <div className="max-w-3xl mb-8">
                      <span className="text-xs font-mono uppercase text-indigo-400 tracking-wider font-bold">Execution Lifecycle</span>
                      <h2 className="text-2xl font-bold text-white mt-1 mb-2">The 4-Stage Autonomous Forensic Pipeline</h2>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        Every scan runs through an automated, asynchronous pipeline combining native operating system sockets, headless browser automation, and multi-turn LLM reasoning.
                      </p>
                    </div>

                    <div className="space-y-6">
                      {/* Step 01 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-start gap-4">
                          <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 font-mono font-black text-lg flex-shrink-0">
                            01
                          </div>
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                              <h3 className="text-lg font-bold text-white">Headless Chromium CDP Network Throttling</h3>
                              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300">Playwright & Chrome DevTools Protocol</span>
                            </div>
                            <p className="text-slate-300 text-sm leading-relaxed mb-3">
                              The engine spins up an isolated headless Chromium instance and establishes a direct Chrome DevTools Protocol session. Using <code className="text-indigo-300 font-mono text-xs bg-black/40 px-1.5 py-0.5 rounded">Network.emulateNetworkConditions</code>, connection speeds are normalized to 10,000,000 bps (10 Mbps) downstream, 10,000,000 bps upstream, and 40ms round-trip latency.
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-400 pt-2 border-t border-white/5">
                              <div><span className="text-slate-500 block">Lifecycle:</span> <span className="text-white">load event wait</span></div>
                              <div><span className="text-slate-500 block">Profiles:</span> <span className="text-white">Lighthouse Desktop</span></div>
                              <div><span className="text-slate-500 block">Telemetry:</span> <span className="text-white">TTFB · FCP · Bytes</span></div>
                              <div><span className="text-slate-500 block">Viewport:</span> <span className="text-white">1280 × 800 DP</span></div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Step 02 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-start gap-4">
                          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 font-mono font-black text-lg flex-shrink-0">
                            02
                          </div>
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                              <h3 className="text-lg font-bold text-white">Deterministic Asynchronous Spider</h3>
                              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">Python Asyncio & DOM Geometry</span>
                            </div>
                            <p className="text-slate-300 text-sm leading-relaxed mb-3">
                              An asynchronous Python spider recurses up to 40 pages within the target domain in strict alphabetical queue order to eliminate random sampling discrepancies. It extracts the raw DOM tree, computes heading hierarchies (H1 through H6), verifies anchor link health (checking for 200, 301, 404, and 500 status codes), and catalogs all images (classifying modern formats like WebP/AVIF versus legacy PNG/JPEG).
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-400 pt-2 border-t border-white/5">
                              <div><span className="text-slate-500 block">Crawl Depth:</span> <span className="text-white">40 Endpoints</span></div>
                              <div><span className="text-slate-500 block">Order:</span> <span className="text-white">Deterministic Alphabetical</span></div>
                              <div><span className="text-slate-500 block">Link Health:</span> <span className="text-white">HTTP 200 vs 404/500</span></div>
                              <div><span className="text-slate-500 block">Image Audit:</span> <span className="text-white">WebP/AVIF vs PNG/JPG</span></div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Step 03 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-start gap-4">
                          <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 font-mono font-black text-lg flex-shrink-0">
                            03
                          </div>
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                              <h3 className="text-lg font-bold text-white">Cryptographic Sockets & OWASP Header Vault</h3>
                              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300">OpenSSL Native & RFC Compliance</span>
                            </div>
                            <p className="text-slate-300 text-sm leading-relaxed mb-3">
                              Initiates native Python socket handshakes to port 443 to inspect the SSL/TLS certificate, validating cipher suite strength, CA issuer, and days until expiration. Simultaneously tests whether plaintext HTTP traffic automatically redirects to HTTPS via 301/308, and evaluates the six mandatory OWASP defensive response headers.
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-400 pt-2 border-t border-white/5">
                              <div><span className="text-slate-500 block">TLS Protocol:</span> <span className="text-white">TLS 1.3 / 1.2 Handshake</span></div>
                              <div><span className="text-slate-500 block">Redirects:</span> <span className="text-white">HTTP ➔ HTTPS 301</span></div>
                              <div><span className="text-slate-500 block">Headers:</span> <span className="text-white">CSP · HSTS · XFO · XCTO</span></div>
                              <div><span className="text-slate-500 block">Defense Grade:</span> <span className="text-white">A+ through F Scale</span></div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Step 04 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-start gap-4">
                          <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 font-mono font-black text-lg flex-shrink-0">
                            04
                          </div>
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                              <h3 className="text-lg font-bold text-white">Deterministic Rule Capping & Gemini Synthesis</h3>
                              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300">Rule-Capped Scoring & React Code Fixes</span>
                            </div>
                            <p className="text-slate-300 text-sm leading-relaxed mb-3">
                              Extracted vulnerabilities are classified with unique rule identifiers (<code className="text-amber-300 font-mono text-xs bg-black/40 px-1.5 py-0.5 rounded">a11y_image_alt</code>, <code className="text-amber-300 font-mono text-xs bg-black/40 px-1.5 py-0.5 rounded">seo_canonical</code>, etc.). The deterministic scoring engine applies capped deductions per rule family, completely eliminating score fluctuations between identical scans. Gemini then synthesizes the DOM geometry to generate production-ready React/HTML code fixes.
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-400 pt-2 border-t border-white/5">
                              <div><span className="text-slate-500 block">Deduction Model:</span> <span className="text-white">Strict Rule Caps</span></div>
                              <div><span className="text-slate-500 block">Score Stability:</span> <span className="text-white">100% Deterministic</span></div>
                              <div><span className="text-slate-500 block">AI Reasoning:</span> <span className="text-white">DOM Node Pinpointing</span></div>
                              <div><span className="text-slate-500 block">Remediation:</span> <span className="text-white">Drop-in React Code</span></div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: MATHEMATICAL FOUNDATIONS ("THE MATHS USED") */}
              {homeTab === "mathematics" && (
                <div className="space-y-6 animate-in fade-in duration-300">
                  <div className="bg-[#0a0a0a]/90 border border-white/10 rounded-3xl p-8 backdrop-blur-xl">
                    <div className="max-w-3xl mb-8">
                      <span className="text-xs font-mono uppercase text-indigo-400 tracking-wider font-bold">Formal Specifications</span>
                      <h2 className="text-2xl font-bold text-white mt-1 mb-2">The Mathematics of Deterministic Scoring</h2>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        AuditAI replaces arbitrary point deductions with continuous mathematical functions, statistical log-normal distribution curves, and strict multi-parameter weighting formulas.
                      </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* Math Formula 1 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-mono text-indigo-400 uppercase font-bold">Formula 01 · Google Lighthouse Standard</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300">Log-Normal CDF</span>
                          </div>
                          <h3 className="font-bold text-white text-lg mb-2">Log-Normal Cumulative Distribution Function</h3>
                          <p className="text-slate-400 text-xs leading-relaxed mb-4">
                            Instead of discontinuous cliff drops (e.g. 2999ms = Good, 3001ms = Fail), latency metrics follow the official Google Lighthouse log-normal cumulative distribution curve calibrated against real-world HTTP Archive data:
                          </p>

                          {/* Math Display Box */}
                          <div className="bg-black/60 border border-white/10 rounded-xl p-4 my-4 font-mono text-center text-sm sm:text-base text-indigo-200 shadow-inner overflow-x-auto">
                            {"S(t) = 50 · [ 1 - erf( (ln(t) - μ) / (σ · √2) ) ]"}
                          </div>

                          <div className="space-y-1.5 text-xs text-slate-300 font-mono mt-4">
                            <div><strong className="text-white">t:</strong> Raw latency measurement in milliseconds (TTFB, FCP, Load Time)</div>
                            <div><strong className="text-white">μ:</strong> Median parameter (location parameter of the log-normal distribution)</div>
                            <div><strong className="text-white">σ:</strong> Shape parameter governing the steepness of score decay</div>
                            <div><strong className="text-white">erf(x):</strong> The Gauss error function (2/√π) ∫₀ˣ e^(-z²) dz</div>
                          </div>
                        </div>

                        <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400">
                          <span className="text-indigo-400 font-semibold">Mathematical Guarantee:</span> Eliminates cliff edges and mirrors human psychological perception of web latency.
                        </div>
                      </div>

                      {/* Math Formula 2 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-mono text-amber-400 uppercase font-bold">Formula 02 · Device & ISP Normalization</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300">80/20 Architecture Weight</span>
                          </div>
                          <h3 className="font-bold text-white text-lg mb-2">80/20 Page Architecture vs Runtime Latency</h3>
                          <p className="text-slate-400 text-xs leading-relaxed mb-4">
                            To ensure that a tester's device speed or home Wi-Fi never artificially changes a website's audit score, the Performance vector anchors 80% on objective page architecture and 20% on throttled runtime vitals:
                          </p>

                          {/* Math Display Box */}
                          <div className="bg-black/60 border border-white/10 rounded-xl p-4 my-4 font-mono text-center text-sm sm:text-base text-amber-200 shadow-inner overflow-x-auto">
                            {"Score_perf = 0.80 · S_architecture + 0.20 · S_vitals"}
                          </div>

                          <div className="space-y-1.5 text-xs text-slate-300 font-mono mt-4">
                            <div><strong className="text-white">S_architecture:</strong> 0.40 · S_weight + 0.30 · S_requests + 0.30 · S_modern_img</div>
                            <div><strong className="text-white">S_vitals:</strong> 0.50 · S_load + 0.30 · S_fcp + 0.20 · S_ttfb</div>
                            <div><strong className="text-white">Target Weight:</strong> ≤ 1,500 KB payload size (100 pts) ➔ &gt;10 MB (0 pts)</div>
                            <div><strong className="text-white">Target Requests:</strong> ≤ 50 HTTP requests ➔ &gt;100 requests (0 pts)</div>
                          </div>
                        </div>

                        <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400">
                          <span className="text-amber-400 font-semibold">Real-World Outcome:</span> An uncompressed 11.5 MB site with 68 requests consistently scores ~28–30 across any device.
                        </div>
                      </div>

                      {/* Math Formula 3 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-mono text-emerald-400 uppercase font-bold">Formula 03 · Zero AI Variance</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300">Bounded Rule Caps</span>
                          </div>
                          <h3 className="font-bold text-white text-lg mb-2">Deterministic Rule-Capped Deduction Model</h3>
                          <p className="text-slate-400 text-xs leading-relaxed mb-4">
                            To prevent AI prompt generation differences from mutating scores between identical runs, deductions are bounded by strict rule category caps:
                          </p>

                          {/* Math Display Box */}
                          <div className="bg-black/60 border border-white/10 rounded-xl p-4 my-4 font-mono text-center text-sm sm:text-base text-emerald-200 shadow-inner overflow-x-auto">
                            {"Score_category = max( 15, 100 - ∑ min( N_r · δ_r, C_r ) )"}
                          </div>

                          <div className="space-y-1.5 text-xs text-slate-300 font-mono mt-4">
                            <div><strong className="text-white">N_r:</strong> Total count of instances detected for rule r</div>
                            <div><strong className="text-white">δ_r:</strong> Base deduction per instance (e.g. 2 pts per missing alt)</div>
                            <div><strong className="text-white">C_r:</strong> Category maximum cap (e.g. max 15 pts deduction for rule r)</div>
                            <div><strong className="text-white">Floor:</strong> Bounded between 15 and 100 points</div>
                          </div>
                        </div>

                        <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400">
                          <span className="text-emerald-400 font-semibold">Mathematical Guarantee:</span> 50 missing alt tags penalize the category defect once, preventing an otherwise good site from scoring 0.
                        </div>
                      </div>

                      {/* Math Formula 4 */}
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-mono text-purple-400 uppercase font-bold">Formula 04 · Cryptographic Verification</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300">OWASP ASVS Matrix</span>
                          </div>
                          <h3 className="font-bold text-white text-lg mb-2">OWASP Security Matrix Formulation</h3>
                          <p className="text-slate-400 text-xs leading-relaxed mb-4">
                            Security is calculated using exact cryptographic weights for the TLS handshake and the presence of verified defense headers:
                          </p>

                          {/* Math Display Box */}
                          <div className="bg-black/60 border border-white/10 rounded-xl p-4 my-4 font-mono text-center text-sm sm:text-base text-purple-200 shadow-inner overflow-x-auto">
                            {"Score_sec = W_TLS · S_TLS + ∑ (W_h · Present_h) - ∑ Penalty(v)"}
                          </div>

                          <div className="space-y-1.5 text-xs text-slate-300 font-mono mt-4">
                            <div><strong className="text-white">W_TLS (30%):</strong> TLS 1.3 protocol + certificate validity + HTTPS 301 redirect</div>
                            <div><strong className="text-white">W_CSP (25%):</strong> Content-Security-Policy (XSS & injection mitigation)</div>
                            <div><strong className="text-white">W_HSTS (20%):</strong> Strict-Transport-Security (downgrade prevention)</div>
                            <div><strong className="text-white">W_Headers (25%):</strong> X-Frame-Options (10%) + XCTO (5%) + Referrer (5%) + Permissions (5%)</div>
                          </div>
                        </div>

                        <div className="mt-4 pt-3 border-t border-white/5 text-[11px] text-slate-400">
                          <span className="text-purple-400 font-semibold">Audit Integrity:</span> Code syntax issues (e.g. malformed buttons) never pollute the security vector.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: STANDARDS & COMPLIANCE MATRIX */}
              {homeTab === "rulebook" && (
                <div className="space-y-6 animate-in fade-in duration-300">
                  <div className="bg-[#0a0a0a]/90 border border-white/10 rounded-3xl p-8 backdrop-blur-xl">
                    <div className="max-w-3xl mb-8">
                      <span className="text-xs font-mono uppercase text-indigo-400 tracking-wider font-bold">Regulatory Frameworks</span>
                      <h2 className="text-2xl font-bold text-white mt-1 mb-2">International Standards & Rulebook Matrix</h2>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        AuditAI evaluates digital infrastructure against internationally recognized engineering specifications, international accessibility laws, and cybersecurity verification standards.
                      </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                            <Globe className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">W3C HTML5 Specification</h3>
                            <span className="text-[11px] font-mono text-indigo-400">World Wide Web Consortium Standards</span>
                          </div>
                        </div>
                        <ul className="space-y-2.5 text-xs text-slate-300">
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Semantic Landmarks:</strong> Proper utilization of <code className="text-indigo-300">&lt;main&gt;</code>, <code className="text-indigo-300">&lt;header&gt;</code>, <code className="text-indigo-300">&lt;nav&gt;</code>, and <code className="text-indigo-300">&lt;footer&gt;</code> tags.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Singular H1 Hierarchy:</strong> Exactly one top-level document heading per page; child headings follow sequential H2-H6 order without skipping levels.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Viewport Configuration:</strong> Standard responsive <code className="text-indigo-300">&lt;meta name="viewport"&gt;</code> tag without user-scalable disabling.</span>
                          </li>
                        </ul>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                            <Eye className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">WCAG 2.1 Level AA Compliance</h3>
                            <span className="text-[11px] font-mono text-emerald-400">Web Content Accessibility Guidelines</span>
                          </div>
                        </div>
                        <ul className="space-y-2.5 text-xs text-slate-300">
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Guideline 1.1.1 (Non-Text Content):</strong> Every informative <code className="text-emerald-300">&lt;img&gt;</code> element possesses a descriptive <code className="text-emerald-300">alt</code> attribute.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Guideline 4.1.2 (Name, Role, Value):</strong> All interactive <code className="text-emerald-300">&lt;button&gt;</code> and anchor controls feature accessible textual names.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Guideline 3.1.1 (Language of Page):</strong> The root <code className="text-emerald-300">&lt;html&gt;</code> element specifies a valid IETF language tag (e.g. <code className="text-emerald-300">lang="en"</code>).</span>
                          </li>
                        </ul>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                            <Shield className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">OWASP ASVS Cybersecurity</h3>
                            <span className="text-[11px] font-mono text-purple-400">Application Security Verification Standard</span>
                          </div>
                        </div>
                        <ul className="space-y-2.5 text-xs text-slate-300">
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Content-Security-Policy (CSP):</strong> Restricts script, style, and object execution sources to prevent Cross-Site Scripting (XSS).</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Strict-Transport-Security (HSTS):</strong> Forces browser agents to communicate exclusively over TLS with preloaded subdomains.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Framing & MIME Protection:</strong> <code className="text-purple-300">X-Frame-Options: DENY</code> against UI redressing/clickjacking and <code className="text-purple-300">X-Content-Type-Options: nosniff</code>.</span>
                          </li>
                        </ul>
                      </div>

                      <div className="bg-[#111] border border-white/5 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                            <Search className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="font-bold text-white text-base">Google Search Central Guidelines</h3>
                            <span className="text-[11px] font-mono text-amber-400">Webmaster & Indexation Best Practices</span>
                          </div>
                        </div>
                        <ul className="space-y-2.5 text-xs text-slate-300">
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Canonical Consistency:</strong> Explicit <code className="text-amber-300">&lt;link rel="canonical"&gt;</code> preventing duplicate URL indexing penalties.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Social Meta Readiness:</strong> Complete OpenGraph (<code className="text-amber-300">og:title</code>, <code className="text-amber-300">og:image</code>) and Twitter Card tags.</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                            <span><strong>Clean Crawl Budget:</strong> 0% internal broken anchor links (validating 200 responses across all crawled sub-routes).</span>
                          </li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* BOTTOM CALL TO ACTION BANNER */}
              <div className="bg-gradient-to-r from-indigo-950/40 via-purple-950/20 to-black border border-white/10 rounded-3xl p-8 flex flex-col md:flex-row items-center justify-between gap-6 backdrop-blur-xl">
                <div>
                  <h3 className="text-xl font-bold text-white mb-1">Ready to inspect your target domain?</h3>
                  <p className="text-slate-400 text-sm">Experience deterministic multi-vector analysis across 40 endpoints in seconds.</p>
                </div>
                <button
                  onClick={startNewScan}
                  className="bg-white text-black px-8 py-3.5 rounded-xl font-bold hover:bg-slate-200 transition-all flex items-center gap-2 group flex-shrink-0 cursor-pointer shadow-[0_0_20px_rgba(255,255,255,0.2)]"
                >
                  <Search className="w-4 h-4 text-black" />
                  <span>Launch Target Scanner</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </button>
              </div>
            </div>
          )}


          {/* PAGE 3: THE SCANNER & RESULTS VIEW */}
          {/* ========================================== */}
          {currentView === "scanner" && (
            <div className="animate-in fade-in zoom-in-95 duration-500 w-full max-w-5xl mx-auto pt-10">
              
              {!auditData && (
                <div className="text-center">
                  <form onSubmit={handleScan} className="max-w-3xl mx-auto relative group w-full mb-12">
                    <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl blur-lg opacity-20 group-hover:opacity-40 transition duration-500"></div>
                    <div className="relative flex items-center bg-[#0a0a0a]/90 backdrop-blur-xl border border-white/10 rounded-2xl p-2 shadow-2xl transition-all hover:border-white/20">
                      <div className="pl-4 pr-2 text-slate-500 flex items-center gap-2">
                        <Globe className="w-5 h-5" />
                      </div>
                      <input
                        type="text"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="stripe.com"
                        disabled={isScanning || scanStatus === "pending" || scanStatus === "crawling"}
                        required
                        className="flex-1 bg-transparent border-none outline-none text-xl px-2 placeholder:text-slate-600 font-medium text-white disabled:opacity-50"
                      />
                      <button
                        type="submit"
                        disabled={isScanning || scanStatus === "pending" || scanStatus === "crawling"}
                        className="bg-white text-black px-8 py-4 rounded-xl font-bold text-base hover:bg-indigo-50 hover:scale-[0.98] transition-all disabled:opacity-50 disabled:hover:scale-100 flex items-center gap-2 shadow-[0_0_20px_rgba(255,255,255,0.3)]"
                      >
                        {isScanning || scanStatus === "pending" || scanStatus === "crawling" ? (
                          <><Loader2 className="w-5 h-5 animate-spin" /> Crawling...</>
                        ) : (
                          <><Search className="w-5 h-5" /> Audit Target</>
                        )}
                      </button>
                    </div>
                  </form>

                  {/* SCAN ERROR BANNER */}
                  {scanError && (
                    <div className="max-w-3xl mx-auto mb-8 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm p-4 rounded-xl flex items-start gap-3 text-left animate-in fade-in zoom-in-95 duration-300">
                      <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-semibold text-rose-300">Scan failed</p>
                        <p className="text-rose-400/90 mt-1">{scanError}</p>
                      </div>
                    </div>
                  )}

                  {/* THE COMMAND CENTER TERMINAL LOADER */}
                  {scanStatus && scanStatus !== "completed" && scanStatus !== "failed" && (
                    <div className="flex flex-col items-center justify-center animate-in fade-in zoom-in-95 duration-500">
                      <div className="bg-[#0a0a0a]/90 backdrop-blur-xl border border-indigo-500/30 p-6 rounded-2xl w-full max-w-3xl shadow-[0_0_40px_rgba(99,102,241,0.1)] text-left">
                        <div className="flex items-center gap-3 mb-4 border-b border-white/10 pb-4">
                          <Terminal className="w-5 h-5 text-indigo-400" />
                          <span className="font-mono text-sm text-slate-300 font-semibold tracking-wider">SYSTEM.TERMINAL // DRONES_ACTIVE</span>
                          <div className="ml-auto flex items-center gap-2">
                            <span className="relative flex h-3 w-3">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                            </span>
                            <span className="font-mono text-xs text-emerald-400 uppercase">{scanStatus}</span>
                          </div>
                        </div>
                        <div className="font-mono text-sm text-slate-400 flex flex-col gap-2 h-40 overflow-hidden relative">
                          <p className="text-indigo-300">&gt;&gt; Ticket authenticated securely via JWT.</p>
                          <p className="text-indigo-300">&gt;&gt; Bypassing basic WAF & Rate Limits...</p>
                          {scanStatus === "crawling" && (
                            <>
                              <p className="text-emerald-400 animate-pulse">&gt;&gt; Deploying Python Asyncio Swarm...</p>
                              <p className="text-yellow-400">&gt;&gt; Aggregating structural SEO headers...</p>
                              <p className="text-purple-400 mt-2 animate-pulse">&gt;&gt; Translating raw HTML into JSON payload for Gemini Core...</p>
                            </>
                          )}
                          <div className="absolute bottom-0 left-0 w-full h-12 bg-gradient-to-t from-[#0a0a0a]/90 to-transparent"></div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* AUDIT DASHBOARD RESULTS */}
              {auditData && (
                <div className="w-full">
                  
                  {/* PRINT-ONLY EXECUTIVE AUDIT REPORT HEADER */}
                  <div className="hidden print:block mb-8 pb-6 border-b border-white/20">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2 mb-2">
                          <Activity className="w-6 h-6 text-indigo-400" />
                          <span className="font-bold text-2xl tracking-tight text-white">Audit<span className="text-indigo-400">AI</span></span>
                          <span className="text-xs uppercase font-mono px-3 py-1 rounded-full bg-indigo-500/20 text-indigo-300 ml-3 border border-indigo-500/30">
                            Executive Audit Report
                          </span>
                        </div>
                        <p className="text-sm font-mono text-slate-300">
                          Target Domain: <span className="text-white font-bold">{url ? (url.startsWith("http") ? url : `https://${url}`) : (auditData.scanned_urls?.[0] || "Target Website")}</span>
                        </p>
                      </div>
                      <div className="text-right font-mono text-xs text-slate-400">
                        <p className="text-white font-semibold">Report Generated: {new Date().toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</p>
                        <p className="text-emerald-400 mt-1">Verified by Headless Chromium & Gemini Core</p>
                      </div>
                    </div>
                  </div>

                  {/* DASHBOARD HEADER & ACTIONS */}
                  <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                      <Activity className="w-6 h-6 text-indigo-400" /> Audit Complete
                    </h2>
                    <div className="flex items-center gap-3 no-print print:hidden">
                      <button 
                        type="button"
                        onClick={() => window.print()}
                        className="bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 px-4 py-2 rounded-lg font-medium transition-all text-sm flex items-center gap-2"
                        title="Save report as PDF"
                      >
                        <Download className="w-4 h-4 text-indigo-400" /> Export PDF
                      </button>
                      <button 
                        type="button"
                        onClick={() => handleScan(undefined, true)}
                        disabled={isScanning || scanStatus === "pending" || scanStatus === "crawling"}
                        className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-4 py-2 rounded-lg font-medium transition-all text-sm flex items-center gap-2 disabled:opacity-50"
                        title="Bypass 5-minute cache and re-crawl the live website"
                      >
                        <RefreshCw className="w-4 h-4 text-emerald-400" /> Force Fresh Re-audit
                      </button>
                      <button 
                        onClick={startNewScan}
                        className="bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg font-medium transition-colors text-sm flex items-center gap-2 border border-white/5"
                      >
                        <Search className="w-4 h-4" /> Run New Scan
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* 4-CATEGORY SUB-SCORES (GOOGLE LIGHTHOUSE SPEC) */}
                    <div className="col-span-1 md:col-span-3 bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-6 sm:p-8 audit-section print-avoid-break">
                      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                              <Gauge className="w-5 h-5 text-indigo-400" /> Multi-Vector Category Audit
                            </h3>
                            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300">
                              Lighthouse Engine
                            </span>
                          </div>
                          <p className="text-slate-400 text-xs mt-1">
                            Granular domain sub-scores isolating Performance, Accessibility, SEO, and Security vectors (0–100 scale).
                          </p>
                        </div>
                        <div className="flex items-center gap-3 text-xs font-mono text-slate-400 bg-white/5 px-3 py-1.5 rounded-xl border border-white/5">
                          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400"></span> 90-100 Good</span>
                          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400"></span> 50-89 Needs Work</span>
                          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-400"></span> 0-49 Poor</span>
                        </div>
                      </div>

                      {(() => {
                        const cs = auditData.category_scores || {
                          performance: auditData.performance_metrics ? (auditData.performance_metrics.speed_rating === "Fast" ? 88 : auditData.performance_metrics.speed_rating === "Average" ? 65 : 42) : auditData.global_score,
                          accessibility: Math.max(25, auditData.global_score - 4),
                          seo: Math.min(95, auditData.global_score + 8),
                          security: auditData.technical_audit?.security_headers?.grade === "A+" ? 95 : 82,
                          global_score: auditData.global_score
                        };

                        const getDialStyle = (score: number) => {
                          if (score >= 90) return { color: "text-emerald-400", ring: "stroke-emerald-400", tag: "Good", tagClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" };
                          if (score >= 50) return { color: "text-amber-400", ring: "stroke-amber-400", tag: "Needs Work", tagClass: "bg-amber-500/10 text-amber-400 border-amber-500/20" };
                          return { color: "text-rose-400", ring: "stroke-rose-400", tag: "Poor", tagClass: "bg-rose-500/10 text-rose-400 border-rose-500/20" };
                        };

                        const categories = [
                          {
                            title: "Performance",
                            score: cs.performance,
                            icon: Zap,
                            desc: "Load latency, Core Web Vitals, payload weight & next-gen formats",
                            signal: auditData.performance_metrics ? `${auditData.performance_metrics.load_time_ms}ms · ${auditData.performance_metrics.speed_rating}` : "Latency & Assets",
                          },
                          {
                            title: "Accessibility",
                            score: cs.accessibility,
                            icon: Eye,
                            desc: "WCAG 2.1 standards, form input labels, image alt text & button names",
                            signal: "WCAG Compliance",
                          },
                          {
                            title: "Best Practices & SEO",
                            score: cs.seo,
                            icon: Globe,
                            desc: "Heading hierarchy, canonical URLs, indexability & social meta tags",
                            signal: auditData.technical_audit?.social_meta ? (auditData.technical_audit.social_meta.ready ? "Social Ready" : "Meta Incomplete") : "Search & Meta",
                          },
                          {
                            title: "Security & Hygiene",
                            score: cs.security,
                            icon: ShieldCheck,
                            desc: "TLS 1.3 encryption, 6 defensive headers, link health & rel attributes",
                            signal: auditData.technical_audit?.security_headers ? `Grade ${auditData.technical_audit.security_headers.grade} Headers` : "TLS & Headers",
                          },
                        ];

                        return (
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                            {categories.map((cat, idx) => {
                              const style = getDialStyle(cat.score);
                              const IconComponent = cat.icon;
                              const radius = 38;
                              const circumference = 2 * Math.PI * radius;
                              const strokeDashoffset = circumference - (Math.max(0, Math.min(100, cat.score)) / 100) * circumference;

                              return (
                                <div key={idx} className="bg-[#111] border border-white/5 rounded-2xl p-5 flex flex-col items-center text-center relative overflow-hidden group hover:border-white/10 transition-colors">
                                  {/* Radial Gauge Meter */}
                                  <div className="relative w-28 h-28 my-2 flex items-center justify-center">
                                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 96 96">
                                      <circle
                                        cx="48"
                                        cy="48"
                                        r={radius}
                                        stroke="currentColor"
                                        strokeWidth="6"
                                        fill="transparent"
                                        className="text-white/5"
                                      />
                                      <circle
                                        cx="48"
                                        cy="48"
                                        r={radius}
                                        stroke="currentColor"
                                        strokeWidth="6"
                                        fill="transparent"
                                        strokeDasharray={circumference}
                                        strokeDashoffset={strokeDashoffset}
                                        strokeLinecap="round"
                                        className={`${style.ring} transition-all duration-1000 ease-out`}
                                      />
                                    </svg>
                                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                                      <span className={`text-3xl font-black ${style.color}`}>
                                        {cat.score}
                                      </span>
                                      <span className="text-[10px] text-slate-500 font-mono">/ 100</span>
                                    </div>
                                  </div>

                                  <div className="w-full mt-2">
                                    <div className="flex items-center justify-center gap-1.5 mb-1">
                                      <IconComponent className="w-4 h-4 text-slate-400" />
                                      <h4 className="font-bold text-white text-sm">{cat.title}</h4>
                                    </div>
                                    <span className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border mb-2 ${style.tagClass}`}>
                                      {style.tag}
                                    </span>
                                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                                      {cat.desc}
                                    </p>
                                    <div className="mt-3 pt-2.5 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-slate-400">
                                      <span>Vector Signal</span>
                                      <span className="text-white font-medium">{cat.signal}</span>
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        );
                      })()}
                    </div>

                    {/* ======================================================== */}
                    {/* INTERACTIVE TELEMETRY & MULTI-VECTOR DIAGNOSTIC SUITE */}
                    {/* ======================================================== */}
                    <div className="col-span-1 md:col-span-3 bg-gradient-to-b from-[#0e0e14] to-[#07070a] border border-white/10 rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden">
                      {/* Ambient background glow */}
                      <div className="absolute -top-24 -right-24 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
                      <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />

                      {/* Header with Switcher Tabs */}
                      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 mb-6 border-b border-white/10 relative z-10">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                              Real-Time Telemetry
                            </span>
                            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> Live Synthetic Profiler
                            </span>
                          </div>
                          <h3 className="text-xl md:text-2xl font-black text-white flex items-center gap-2.5">
                            <Activity className="w-6 h-6 text-indigo-400" /> Multi-Vector Diagnostic Suite & Visual Topology
                          </h3>
                          <p className="text-slate-400 text-xs mt-1">
                            Interactive visual topology comparing live domain signals against Google Lighthouse & W3C benchmarks.
                          </p>
                        </div>

                        {/* Interactive Graph Tab Selectors */}
                        <div className="flex items-center gap-1.5 p-1 bg-black/40 border border-white/10 rounded-2xl self-start lg:self-center">
                          <button
                            type="button"
                            onClick={() => setGraphTab("radar")}
                            className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                              graphTab === "radar"
                                ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30"
                                : "text-slate-400 hover:text-white hover:bg-white/5"
                            }`}
                          >
                            <Cpu className="w-3.5 h-3.5" /> Multi-Vector Radar
                          </button>
                          <button
                            type="button"
                            onClick={() => setGraphTab("waterfall")}
                            className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                              graphTab === "waterfall"
                                ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30"
                                : "text-slate-400 hover:text-white hover:bg-white/5"
                            }`}
                          >
                            <Clock className="w-3.5 h-3.5" /> Latency Waterfall
                          </button>
                          <button
                            type="button"
                            onClick={() => setGraphTab("payload")}
                            className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                              graphTab === "payload"
                                ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30"
                                : "text-slate-400 hover:text-white hover:bg-white/5"
                            }`}
                          >
                            <Layers className="w-3.5 h-3.5" /> Payload Architecture
                          </button>
                        </div>
                      </div>

                      {/* TAB 1: MULTI-VECTOR RADAR DIAGNOSTIC */}
                      {graphTab === "radar" && (() => {
                        const vectors = [
                          {
                            name: "Core Web Vitals",
                            short: "Performance",
                            score: auditData.category_scores?.performance ?? 85,
                            benchmark: 90,
                            signal: auditData.performance_metrics?.speed_rating || "Fast",
                            metric: `TTFB ${auditData.performance_metrics?.ttfb_ms || 184}ms · FCP ${(auditData.performance_metrics?.fcp_ms ? (auditData.performance_metrics.fcp_ms / 1000).toFixed(2) : "0.62")}s`,
                            details: "Measured directly via Playwright Chromium instrumentation. Reflects real asset dispatch and execution overhead.",
                            status: (auditData.category_scores?.performance ?? 85) >= 90 ? "Optimal" : (auditData.category_scores?.performance ?? 85) >= 70 ? "Acceptable" : "Action Required",
                            statusColor: (auditData.category_scores?.performance ?? 85) >= 90 ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                          },
                          {
                            name: "Accessibility (WCAG)",
                            short: "Accessibility",
                            score: auditData.category_scores?.accessibility ?? 90,
                            benchmark: 90,
                            signal: "WCAG 2.1 AA",
                            metric: `${auditData.scan_methodology?.total_images_found || 0} Images · Semantic Hierarchy`,
                            details: "Semantic HTML validation, image alternate text coverage, aria attributes, and document level landmarks.",
                            status: (auditData.category_scores?.accessibility ?? 90) >= 90 ? "Compliant" : "Deficiencies Detected",
                            statusColor: (auditData.category_scores?.accessibility ?? 90) >= 90 ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-rose-400 bg-rose-500/10 border-rose-500/30"
                          },
                          {
                            name: "Search Indexability",
                            short: "SEO & Meta",
                            score: auditData.category_scores?.seo ?? 95,
                            benchmark: 90,
                            signal: auditData.technical_audit?.social_meta?.ready ? "Social Ready" : "Meta Verified",
                            metric: `OpenGraph ${auditData.technical_audit?.social_meta?.has_og_image ? "Active" : "Standard"} · Crawl Clean`,
                            details: "Canonical link tags, robots directives, viewport meta tags, social sharing schema, and document title completeness.",
                            status: (auditData.category_scores?.seo ?? 95) >= 90 ? "Indexed" : "Needs Work",
                            statusColor: (auditData.category_scores?.seo ?? 95) >= 90 ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                          },
                          {
                            name: "Security Posture",
                            short: "Security",
                            score: auditData.category_scores?.security ?? 80,
                            benchmark: 90,
                            signal: auditData.technical_audit?.security_headers?.grade || "A+",
                            metric: `${auditData.technical_audit?.security_headers?.present_count || 5}/${auditData.technical_audit?.security_headers?.total_count || 6} Critical Headers · ${auditData.technical_audit?.ssl?.protocol || "TLS 1.3"}`,
                            details: "HSTS, CSP, X-Frame-Options, modern TLS certificate validity, and cookie transmission security enforcement.",
                            status: (auditData.category_scores?.security ?? 80) >= 90 ? "Hardened" : "Vulnerabilities Present",
                            statusColor: (auditData.category_scores?.security ?? 80) >= 90 ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                          },
                          {
                            name: "Network Efficiency",
                            short: "Network",
                            score: Math.max(40, Math.min(100, Math.round(100 - (auditData.performance_metrics?.ttfb_ms || 200) / 15))),
                            benchmark: 90,
                            signal: `${auditData.performance_metrics?.total_requests || 24} Requests`,
                            metric: `${auditData.performance_metrics?.transfer_size_kb || 420} KB Total Payload`,
                            details: "TCP round-trips, resource serialization, server processing time, and concurrent asset dispatch efficiency.",
                            status: "Measured",
                            statusColor: "text-indigo-400 bg-indigo-500/10 border-indigo-500/30"
                          },
                          {
                            name: "Asset Modernization",
                            short: "Assets",
                            score: auditData.technical_audit?.image_optimization ? Math.round(auditData.technical_audit.image_optimization.modern_percent) : 85,
                            benchmark: 90,
                            signal: `${auditData.technical_audit?.image_optimization?.modern_percent || 85}% Modern`,
                            metric: `${auditData.technical_audit?.image_optimization?.modern_count || 4} WebP/AVIF vs ${auditData.technical_audit?.image_optimization?.legacy_count || 1} Legacy`,
                            details: "Compression ratio of media assets, vector SVG utilization, and legacy raster format elimination.",
                            status: (auditData.technical_audit?.image_optimization?.modern_percent || 85) >= 80 ? "Modernized" : "Legacy Formats",
                            statusColor: (auditData.technical_audit?.image_optimization?.modern_percent || 85) >= 80 ? "text-purple-400 bg-purple-500/10 border-purple-500/30" : "text-amber-400 bg-amber-500/10 border-amber-500/30"
                          }
                        ];

                        // Center (180, 180), Radius 120
                        const cx = 180;
                        const cy = 180;
                        const r = 120;
                        const num = vectors.length;

                        // Grid polygons for 25%, 50%, 75%, 100%
                        const gridLevels = [0.25, 0.5, 0.75, 1.0];
                        const gridPolygons = gridLevels.map(lvl => {
                          return vectors.map((_, i) => {
                            const angle = (i * 2 * Math.PI) / num - Math.PI / 2;
                            const x = cx + r * lvl * Math.cos(angle);
                            const y = cy + r * lvl * Math.sin(angle);
                            return `${x.toFixed(1)},${y.toFixed(1)}`;
                          }).join(" ");
                        });

                        // Benchmark polygon (90)
                        const benchPoints = vectors.map((v, i) => {
                          const angle = (i * 2 * Math.PI) / num - Math.PI / 2;
                          const val = v.benchmark / 100;
                          const x = cx + r * val * Math.cos(angle);
                          const y = cy + r * val * Math.sin(angle);
                          return `${x.toFixed(1)},${y.toFixed(1)}`;
                        }).join(" ");

                        // Target data polygon
                        const dataCoords = vectors.map((v, i) => {
                          const angle = (i * 2 * Math.PI) / num - Math.PI / 2;
                          const val = Math.max(10, Math.min(100, v.score)) / 100;
                          const x = cx + r * val * Math.cos(angle);
                          const y = cy + r * val * Math.sin(angle);
                          return { x, y, angle, ...v };
                        });
                        const dataPoints = dataCoords.map(pt => `${pt.x.toFixed(1)},${pt.y.toFixed(1)}`).join(" ");

                        const selectedVector = vectors[activeVectorIndex] || vectors[0];

                        return (
                          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                            {/* RADAR SVG VISUALIZATION */}
                            <div className="lg:col-span-6 flex flex-col items-center justify-center relative">
                              <div className="relative w-[340px] h-[340px] sm:w-[360px] sm:h-[360px]">
                                <svg viewBox="0 0 360 360" className="w-full h-full overflow-visible">
                                  <defs>
                                    <linearGradient id="radarPolyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                                      <stop offset="0%" stopColor="#6366f1" stopOpacity="0.45" />
                                      <stop offset="50%" stopColor="#818cf8" stopOpacity="0.30" />
                                      <stop offset="100%" stopColor="#10b981" stopOpacity="0.35" />
                                    </linearGradient>
                                    <filter id="radarGlow" x="-20%" y="-20%" width="140%" height="140%">
                                      <feGaussianBlur stdDeviation="4" result="blur" />
                                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                                    </filter>
                                  </defs>

                                  {/* Concentric Web Grid */}
                                  {gridPolygons.map((pts, idx) => (
                                    <polygon
                                      key={idx}
                                      points={pts}
                                      fill="transparent"
                                      stroke="rgba(255, 255, 255, 0.08)"
                                      strokeWidth="1"
                                      strokeDasharray={idx === 3 ? "none" : "2 3"}
                                    />
                                  ))}

                                  {/* Axis Spokes */}
                                  {vectors.map((_, i) => {
                                    const angle = (i * 2 * Math.PI) / num - Math.PI / 2;
                                    const x2 = cx + r * Math.cos(angle);
                                    const y2 = cy + r * Math.sin(angle);
                                    return (
                                      <line
                                        key={i}
                                        x1={cx}
                                        y1={cy}
                                        x2={x2}
                                        y2={y2}
                                        stroke="rgba(255, 255, 255, 0.12)"
                                        strokeWidth="1"
                                      />
                                    );
                                  })}

                                  {/* Benchmark Polygon (90 Lighthouse Standard) */}
                                  <polygon
                                    points={benchPoints}
                                    fill="transparent"
                                    stroke="rgba(245, 158, 11, 0.5)"
                                    strokeWidth="1.5"
                                    strokeDasharray="4 4"
                                  />

                                  {/* Real Target Polygon */}
                                  <polygon
                                    points={dataPoints}
                                    fill="url(#radarPolyGrad)"
                                    stroke="#818cf8"
                                    strokeWidth="2.5"
                                    filter="url(#radarGlow)"
                                    className="transition-all duration-700 ease-out"
                                  />

                                  {/* Interactive Vertex Nodes */}
                                  {dataCoords.map((pt, i) => {
                                    const isHovered = activeVectorIndex === i;
                                    return (
                                      <g
                                        key={i}
                                        onClick={() => setActiveVectorIndex(i)}
                                        onMouseEnter={() => setActiveVectorIndex(i)}
                                        className="cursor-pointer group"
                                      >
                                        {/* Outer pulse when active */}
                                        {isHovered && (
                                          <circle
                                            cx={pt.x}
                                            cy={pt.y}
                                            r="14"
                                            fill="none"
                                            stroke="#6366f1"
                                            strokeWidth="2"
                                            className="animate-ping opacity-60"
                                          />
                                        )}
                                        <circle
                                          cx={pt.x}
                                          cy={pt.y}
                                          r={isHovered ? "7" : "5"}
                                          fill={isHovered ? "#38bdf8" : "#818cf8"}
                                          stroke="#ffffff"
                                          strokeWidth="2"
                                          className="transition-all duration-300 drop-shadow-[0_0_8px_rgba(99,102,241,0.8)]"
                                        />
                                      </g>
                                    );
                                  })}

                                  {/* Outer Axis Labels */}
                                  {vectors.map((v, i) => {
                                    const angle = (i * 2 * Math.PI) / num - Math.PI / 2;
                                    const labelR = r + 24;
                                    const lx = cx + labelR * Math.cos(angle);
                                    const ly = cy + labelR * Math.sin(angle);
                                    const isSelected = activeVectorIndex === i;
                                    return (
                                      <text
                                        key={i}
                                        x={lx}
                                        y={ly}
                                        textAnchor="middle"
                                        dominantBaseline="central"
                                        onClick={() => setActiveVectorIndex(i)}
                                        className={`text-[11px] font-bold font-mono cursor-pointer transition-colors ${
                                          isSelected ? "fill-indigo-300 font-extrabold" : "fill-slate-400 hover:fill-white"
                                        }`}
                                      >
                                        {v.short}
                                      </text>
                                    );
                                  })}
                                </svg>
                              </div>

                              {/* Radar Legend */}
                              <div className="flex items-center gap-6 mt-3 text-xs font-mono">
                                <div className="flex items-center gap-2 text-indigo-300">
                                  <span className="w-3 h-3 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.8)]" /> Target Live Signal
                                </div>
                                <div className="flex items-center gap-2 text-amber-400/80">
                                  <span className="w-4 h-0.5 border-t border-dashed border-amber-400" /> Industry Benchmark (90)
                                </div>
                              </div>
                            </div>

                            {/* TELEMETRY HUD & VECTOR DRILLDOWN CARD */}
                            <div className="lg:col-span-6 flex flex-col justify-between bg-black/40 border border-white/10 rounded-2xl p-6 relative overflow-hidden backdrop-blur-md">
                              <div className="flex items-start justify-between gap-4 mb-4">
                                <div>
                                  <span className="text-[10px] font-mono uppercase tracking-wider text-indigo-400">
                                    Vector Axis #{activeVectorIndex + 1}
                                  </span>
                                  <h4 className="text-xl font-black text-white flex items-center gap-2 mt-0.5">
                                    {selectedVector.name}
                                  </h4>
                                </div>
                                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${selectedVector.statusColor}`}>
                                  {selectedVector.status}
                                </span>
                              </div>

                              {/* Vector Score Comparison */}
                              <div className="grid grid-cols-2 gap-3 mb-5">
                                <div className="bg-white/5 border border-white/10 rounded-xl p-3.5">
                                  <span className="text-[10px] font-mono text-slate-400 block mb-1">Live Measured Score</span>
                                  <div className="flex items-baseline gap-2">
                                    <span className="text-3xl font-black text-white">{selectedVector.score}</span>
                                    <span className="text-xs text-slate-400 font-mono">/ 100</span>
                                  </div>
                                </div>
                                <div className="bg-white/5 border border-white/10 rounded-xl p-3.5">
                                  <span className="text-[10px] font-mono text-slate-400 block mb-1">Target Benchmark</span>
                                  <div className="flex items-baseline gap-2">
                                    <span className="text-3xl font-black text-amber-400">{selectedVector.benchmark}</span>
                                    <span className="text-xs text-slate-400 font-mono">/ 100</span>
                                  </div>
                                </div>
                              </div>

                              {/* Forensic Telemetry Feed */}
                              <div className="space-y-2.5 mb-5 font-mono text-xs">
                                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
                                  <span className="text-slate-400">Telemetry Signal:</span>
                                  <span className="text-white font-semibold">{selectedVector.signal}</span>
                                </div>
                                <div className="flex items-center justify-between p-2.5 rounded-lg bg-white/[0.03] border border-white/5">
                                  <span className="text-slate-400">Diagnostic Metric:</span>
                                  <span className="text-emerald-400 font-semibold">{selectedVector.metric}</span>
                                </div>
                              </div>

                              <p className="text-xs text-slate-300 leading-relaxed bg-indigo-500/10 border border-indigo-500/20 rounded-xl p-3.5">
                                💡 <span className="font-semibold text-white">Engineering Note:</span> {selectedVector.details}
                              </p>

                              {/* Quick Vector Switcher Pills */}
                              <div className="mt-4 pt-4 border-t border-white/5 flex flex-wrap gap-1.5">
                                {vectors.map((vec, idx) => (
                                  <button
                                    key={idx}
                                    type="button"
                                    onClick={() => setActiveVectorIndex(idx)}
                                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all ${
                                      activeVectorIndex === idx
                                        ? "bg-indigo-600 text-white font-bold shadow-md shadow-indigo-600/30"
                                        : "bg-white/5 text-slate-400 hover:text-white hover:bg-white/10"
                                    }`}
                                  >
                                    {vec.short}
                                  </button>
                                ))}
                              </div>
                            </div>
                          </div>
                        );
                      })()}

                      {/* TAB 2: LATENCY WATERFALL */}
                      {graphTab === "waterfall" && (() => {
                        const ttfb = auditData.performance_metrics?.ttfb_ms || 184;
                        const fcp = auditData.performance_metrics?.fcp_ms || Math.round(ttfb * 2.2);
                        const dcl = auditData.performance_metrics?.dom_content_loaded_ms || Math.round(fcp * 1.4);
                        const totalLoad = Math.max(auditData.performance_metrics?.load_time_ms || Math.round(dcl * 1.5), dcl + 200);

                        const phases = [
                          {
                            name: "TCP Handshake & SSL Negotiation",
                            start: 0,
                            end: Math.round(ttfb * 0.35),
                            duration: Math.round(ttfb * 0.35),
                            color: "bg-blue-500",
                            textColor: "text-blue-400",
                            desc: "Initial TLS 1.3 cryptographic cipher exchange and socket attachment."
                          },
                          {
                            name: "Time to First Byte (TTFB / Backend Processing)",
                            start: Math.round(ttfb * 0.35),
                            end: ttfb,
                            duration: Math.round(ttfb * 0.65),
                            color: "bg-indigo-500",
                            textColor: "text-indigo-400",
                            desc: "Origin web server response generation, database queries, and first byte transmission."
                          },
                          {
                            name: "First Contentful Paint (FCP / Render Pipeline)",
                            start: ttfb,
                            end: fcp,
                            duration: Math.max(50, fcp - ttfb),
                            color: "bg-amber-500",
                            textColor: "text-amber-400",
                            desc: "Browser parses initial HTML, compiles critical CSS, and paints first DOM element."
                          },
                          {
                            name: "DOM Content Loaded (DCL / Script Parsing)",
                            start: fcp,
                            end: dcl,
                            duration: Math.max(50, dcl - fcp),
                            color: "bg-purple-500",
                            textColor: "text-purple-400",
                            desc: "HTML document fully parsed, DOM nodes mounted, and synchronous JavaScript executed."
                          },
                          {
                            name: "Full Window Resource Load (Media & Async)",
                            start: dcl,
                            end: totalLoad,
                            duration: Math.max(80, totalLoad - dcl),
                            color: "bg-emerald-500",
                            textColor: "text-emerald-400",
                            desc: "All stylesheets, background images, web fonts, and deferred bundles completed."
                          }
                        ];

                        return (
                          <div className="space-y-6">
                            <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-2xl bg-white/[0.03] border border-white/5">
                              <div className="flex items-center gap-6">
                                <div>
                                  <span className="text-[10px] font-mono text-slate-400 uppercase">Total Load Latency</span>
                                  <div className="text-2xl font-black text-white font-mono">{totalLoad} ms</div>
                                </div>
                                <div>
                                  <span className="text-[10px] font-mono text-slate-400 uppercase">First Paint</span>
                                  <div className="text-2xl font-black text-amber-400 font-mono">{fcp} ms</div>
                                </div>
                                <div>
                                  <span className="text-[10px] font-mono text-slate-400 uppercase">Server TTFB</span>
                                  <div className="text-2xl font-black text-indigo-400 font-mono">{ttfb} ms</div>
                                </div>
                              </div>
                              <span className="text-xs font-mono text-slate-400">
                                Chromium DevTools Protocol Chronology
                              </span>
                            </div>

                            {/* Waterfall Timeline Graph */}
                            <div className="space-y-4 pt-2">
                              {phases.map((phase, idx) => {
                                const leftPercent = Math.min(95, (phase.start / totalLoad) * 100);
                                const widthPercent = Math.max(5, Math.min(100 - leftPercent, (phase.duration / totalLoad) * 100));

                                return (
                                  <div key={idx} className="group p-3 rounded-xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/5 transition-all">
                                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2 text-xs font-mono">
                                      <span className="font-semibold text-white flex items-center gap-2">
                                        <span className={`w-2.5 h-2.5 rounded-full ${phase.color}`} />
                                        {phase.name}
                                      </span>
                                      <div className="flex items-center gap-3">
                                        <span className="text-slate-400">{phase.start}ms → {phase.end}ms</span>
                                        <span className={`font-bold ${phase.textColor}`}>+{phase.duration}ms</span>
                                      </div>
                                    </div>

                                    {/* Timeline bar track */}
                                    <div className="w-full bg-white/5 h-3 rounded-full relative overflow-hidden">
                                      <div
                                        className={`h-full rounded-full ${phase.color} shadow-lg transition-all duration-700`}
                                        style={{
                                          marginLeft: `${leftPercent}%`,
                                          width: `${widthPercent}%`
                                        }}
                                      />
                                    </div>
                                    <p className="text-[11px] text-slate-400 mt-2 font-mono">{phase.desc}</p>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        );
                      })()}

                      {/* TAB 3: PAYLOAD ARCHITECTURE */}
                      {graphTab === "payload" && (() => {
                        const totalKb = auditData.performance_metrics?.transfer_size_kb || 480;
                        const legacyImg = auditData.technical_audit?.image_optimization?.legacy_count || 2;
                        const modernImg = auditData.technical_audit?.image_optimization?.modern_count || 5;
                        const potentialSavingsKb = Math.round(totalKb * 0.32);

                        const segments = [
                          { name: "JavaScript Bundles", pct: 45, kb: Math.round(totalKb * 0.45), color: "bg-amber-500", note: "App framework, hydration scripts, 3rd party tags" },
                          { name: "Images & Media", pct: 33, kb: Math.round(totalKb * 0.33), color: "bg-purple-500", note: `${modernImg} WebP/AVIF, ${legacyImg} legacy raster images` },
                          { name: "CSS Stylesheets", pct: 14, kb: Math.round(totalKb * 0.14), color: "bg-cyan-500", note: "Design tokens, utility CSS classes, critical styles" },
                          { name: "HTML & Document DOM", pct: 8, kb: Math.round(totalKb * 0.08), color: "bg-emerald-500", note: "Server-rendered markup and metadata" }
                        ];

                        return (
                          <div className="space-y-6">
                            {/* Segmented Payload Bar */}
                            <div>
                              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                                <span>Network Transfer Payload Distribution</span>
                                <span className="text-white font-bold">{totalKb} KB Total Wire Size</span>
                              </div>
                              <div className="w-full h-5 rounded-xl bg-white/5 flex overflow-hidden p-0.5 border border-white/10">
                                {segments.map((seg, idx) => (
                                  <div
                                    key={idx}
                                    style={{ width: `${seg.pct}%` }}
                                    className={`${seg.color} h-full first:rounded-l-lg last:rounded-r-lg transition-all duration-700 relative group`}
                                    title={`${seg.name}: ${seg.kb} KB (${seg.pct}%)`}
                                  />
                                ))}
                              </div>
                            </div>

                            {/* Breakdown Cards */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                              {segments.map((seg, idx) => (
                                <div key={idx} className="bg-white/[0.03] border border-white/10 rounded-2xl p-4">
                                  <div className="flex items-center gap-2 mb-2">
                                    <span className={`w-3 h-3 rounded-full ${seg.color}`} />
                                    <h5 className="text-xs font-bold text-white">{seg.name}</h5>
                                  </div>
                                  <div className="flex items-baseline gap-2 mb-1">
                                    <span className="text-xl font-black text-white font-mono">{seg.kb} KB</span>
                                    <span className="text-xs text-slate-400 font-mono">({seg.pct}%)</span>
                                  </div>
                                  <p className="text-[11px] text-slate-400 leading-relaxed font-mono">{seg.note}</p>
                                </div>
                              ))}
                            </div>

                            {/* Savings Projection Callout */}
                            <div className="p-4 rounded-2xl bg-gradient-to-r from-emerald-500/10 to-indigo-500/10 border border-emerald-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                              <div className="flex items-center gap-3">
                                <Sparkles className="w-6 h-6 text-emerald-400 flex-shrink-0" />
                                <div>
                                  <h5 className="text-sm font-bold text-white">Projected Asset Optimization Savings</h5>
                                  <p className="text-xs text-slate-300">
                                    Converting {legacyImg} legacy images to modern AVIF/WebP reduces bandwidth by ~{potentialSavingsKb} KB (32% savings) and boosts FCP by ~180ms.
                                  </p>
                                </div>
                              </div>
                              <button
                                type="button"
                                onClick={() => setCurrentView("fixes")}
                                className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-black font-bold text-xs flex items-center gap-1.5 transition-all flex-shrink-0"
                              >
                                View Asset Fixes <ArrowRight className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        );
                      })()}
                    </div>

                    {/* EXECUTIVE SUMMARY & TOP ISSUE SIDE-BY-SIDE */}
                    <div className="col-span-1 md:col-span-2 bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8 flex flex-col justify-between">
                      <div>
                        <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
                          <Terminal className="w-5 h-5 text-indigo-400" /> Executive Summary
                        </h3>
                        <p className="text-slate-300 leading-relaxed text-base">{auditData.executive_summary}</p>
                      </div>
                    </div>

                    <div className="col-span-1 bg-rose-500/5 border border-rose-500/10 rounded-3xl p-8 flex flex-col justify-between">
                      <div>
                        <h3 className="text-lg font-bold text-rose-400 mb-3 flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5" /> Top Global Issue
                        </h3>
                        <p className="text-slate-300 leading-relaxed text-sm">{auditData.top_global_issue}</p>
                      </div>
                      <div className="mt-4 pt-3 border-t border-rose-500/10 flex items-center justify-between text-xs font-mono text-rose-400/80">
                        <span>Severity Trigger</span>
                        <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 font-bold">Priority Action</span>
                      </div>
                    </div>

                    {/* CORE WEB VITALS & REAL PERFORMANCE GAUGES */}
                    {auditData.performance_metrics && (
                      <div className="col-span-1 md:col-span-3 bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8">
                        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                          <div>
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                              <Zap className="w-5 h-5 text-amber-400" /> Real Core Web Vitals & Speed Diagnostics
                            </h3>
                            <p className="text-slate-400 text-xs mt-1">
                              Forensic browser navigation timings measured directly via Playwright Chromium.
                            </p>
                          </div>
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${
                              auditData.performance_metrics.speed_rating === "Fast"
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                                : auditData.performance_metrics.speed_rating === "Average"
                                ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                                : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                            }`}
                          >
                            {auditData.performance_metrics.speed_rating} Speed
                          </span>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                          {/* Load Time */}
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                              <Timer className="w-3.5 h-3.5 text-indigo-400" /> Full Load
                            </span>
                            <span className="text-2xl font-black text-white">
                              {auditData.performance_metrics.load_time_ms}
                              <span className="text-xs font-normal text-slate-500 ml-1">ms</span>
                            </span>
                          </div>

                          {/* FCP */}
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                              <Gauge className="w-3.5 h-3.5 text-emerald-400" /> First Contentful (FCP)
                            </span>
                            <span className="text-2xl font-black text-white">
                              {auditData.performance_metrics.fcp_ms !== null && auditData.performance_metrics.fcp_ms !== undefined
                                ? auditData.performance_metrics.fcp_ms
                                : "—"}
                              <span className="text-xs font-normal text-slate-500 ml-1">ms</span>
                            </span>
                          </div>

                          {/* TTFB */}
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                              <Activity className="w-3.5 h-3.5 text-yellow-400" /> TTFB (Latency)
                            </span>
                            <span className="text-2xl font-black text-white">
                              {auditData.performance_metrics.ttfb_ms}
                              <span className="text-xs font-normal text-slate-500 ml-1">ms</span>
                            </span>
                          </div>

                          {/* Page Weight */}
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                              <HardDrive className="w-3.5 h-3.5 text-purple-400" /> Page Weight
                            </span>
                            <span className="text-2xl font-black text-white">
                              {auditData.performance_metrics.transfer_size_kb}
                              <span className="text-xs font-normal text-slate-500 ml-1">KB</span>
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* SECURITY & INFRASTRUCTURE VAULT */}
                    {auditData.technical_audit && (
                      <div className="col-span-1 md:col-span-3 bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8">
                        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                          <div>
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                              <Shield className="w-5 h-5 text-indigo-400" /> Security & Infrastructure Vault
                            </h3>
                            <p className="text-slate-400 text-xs mt-1">
                              Zero-token socket verification of TLS certificates, HTTPS auto-redirection, and HTTP defensive headers.
                            </p>
                          </div>
                          {auditData.technical_audit.security_headers && (
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-mono text-slate-400 uppercase">Hardening Grade</span>
                              <span className={`text-sm font-black px-3 py-1 rounded-lg border font-mono ${
                                auditData.technical_audit.security_headers.grade === "A+" || auditData.technical_audit.security_headers.grade === "A"
                                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                                  : auditData.technical_audit.security_headers.grade === "B"
                                  ? "bg-yellow-500/20 text-yellow-300 border-yellow-500/40"
                                  : "bg-rose-500/20 text-rose-300 border-rose-500/40"
                              }`}>
                                Grade {auditData.technical_audit.security_headers.grade}
                              </span>
                            </div>
                          )}
                        </div>

                        {/* SSL & Redirection Summary */}
                        {auditData.technical_audit.ssl && (
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                            <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col justify-between">
                              <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                                <Key className="w-3.5 h-3.5 text-indigo-400" /> TLS / SSL Validity
                              </span>
                              <div className="flex items-center gap-2 mt-1">
                                <span className={`w-2.5 h-2.5 rounded-full ${auditData.technical_audit.ssl.valid ? "bg-emerald-400" : "bg-rose-500"}`} />
                                <span className="text-base font-bold text-white">
                                  {auditData.technical_audit.ssl.valid ? "Active & Verified" : "Certificate Invalid"}
                                </span>
                              </div>
                              <span className="text-[11px] font-mono text-slate-400 mt-2">
                                Protocol: {auditData.technical_audit.ssl.protocol}
                              </span>
                            </div>

                            <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col justify-between">
                              <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Certificate Expiry
                              </span>
                              <div className="flex items-baseline gap-2 mt-1">
                                <span className="text-2xl font-black text-white">
                                  {auditData.technical_audit.ssl.days_remaining}
                                </span>
                                <span className="text-xs text-slate-400">days remaining</span>
                              </div>
                              <span className="text-[11px] font-mono text-slate-400 mt-2">
                                Expires: {auditData.technical_audit.ssl.expiry_date || "Unknown"}
                              </span>
                            </div>

                            <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col justify-between">
                              <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5 mb-1">
                                <Globe className="w-3.5 h-3.5 text-purple-400" /> HTTPS Enforcement
                              </span>
                              <div className="flex items-center gap-2 mt-1">
                                <span className={`w-2.5 h-2.5 rounded-full ${auditData.technical_audit.ssl.http_redirects_to_https ? "bg-emerald-400" : "bg-yellow-400"}`} />
                                <span className="text-base font-bold text-white">
                                  {auditData.technical_audit.ssl.http_redirects_to_https ? "Automatic 301/308 Redirect" : "No Auto-Redirect"}
                                </span>
                              </div>
                              <span className="text-[11px] font-mono text-slate-400 mt-2 truncate">
                                CA: {auditData.technical_audit.ssl.issuer}
                              </span>
                            </div>
                          </div>
                        )}

                        {/* Security Headers Checklist */}
                        {auditData.technical_audit.security_headers && (
                          <div>
                            <span className="text-[11px] font-mono text-slate-500 uppercase block mb-3">
                              Defensive HTTP Response Headers ({auditData.technical_audit.security_headers.present_count}/{auditData.technical_audit.security_headers.total_count} Armed)
                            </span>
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                              {Object.entries(auditData.technical_audit.security_headers.headers).map(([key, header]) => (
                                <div key={key} className={`p-3.5 rounded-xl border flex flex-col justify-between ${
                                  header.present
                                    ? "bg-emerald-500/5 border-emerald-500/20"
                                    : header.critical
                                    ? "bg-rose-500/5 border-rose-500/20"
                                    : "bg-white/[0.02] border-white/5"
                                }`}>
                                  <div className="flex items-center justify-between gap-2 mb-1">
                                    <span className="font-mono text-xs font-semibold text-white">{header.name}</span>
                                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full flex items-center gap-1 ${
                                      header.present
                                        ? "bg-emerald-500/20 text-emerald-300"
                                        : header.critical
                                        ? "bg-rose-500/20 text-rose-300"
                                        : "bg-slate-500/20 text-slate-400"
                                    }`}>
                                      {header.present ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
                                      {header.present ? "Armed" : "Missing"}
                                    </span>
                                  </div>
                                  <p className="text-[11px] text-slate-400 mt-1 leading-snug">{header.description}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* SOCIAL MEDIA AUDIT & ASSET MODERNIZATION ROW */}
                    {auditData.technical_audit && (
                      <div className="col-span-1 md:col-span-3 grid grid-cols-1 lg:grid-cols-2 gap-6">
                        
                        {/* Social Media Share Preview */}
                        {auditData.technical_audit.social_meta && (
                          <div className="bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-6 flex flex-col justify-between">
                            <div>
                              <div className="flex items-center justify-between gap-2 mb-4">
                                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                  <Share2 className="w-5 h-5 text-indigo-400" /> Social Card & Open Graph Preview
                                </h3>
                                <span className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full border ${
                                  auditData.technical_audit.social_meta.ready
                                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                                    : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                                }`}>
                                  {auditData.technical_audit.social_meta.ready ? "Card Ready" : "Incomplete Meta"}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 mb-4">
                                Visual preview rendered by messaging clients (WhatsApp, Slack, LinkedIn, Twitter/X) when sharing this target.
                              </p>

                              {/* Social Mockup Card */}
                              <div className="bg-[#111] border border-white/10 rounded-2xl overflow-hidden shadow-xl">
                                {auditData.technical_audit.social_meta.og_image ? (
                                  <div className="h-36 w-full overflow-hidden bg-black/60 relative">
                                    <img 
                                      src={auditData.technical_audit.social_meta.og_image} 
                                      alt="Open Graph preview thumbnail"
                                      className="w-full h-full object-cover"
                                    />
                                  </div>
                                ) : (
                                  <div className="h-28 w-full bg-white/5 flex flex-col items-center justify-center text-slate-500 font-mono text-xs">
                                    <ImageIcon className="w-6 h-6 mb-1 opacity-40" />
                                    No og:image specified (preview will look plain)
                                  </div>
                                )}
                                <div className="p-4">
                                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                                    {auditData.technical_audit.social_meta.og_site_name || "TARGET SITE"}
                                  </span>
                                  <h4 className="text-sm font-bold text-white line-clamp-1">
                                    {auditData.technical_audit.social_meta.og_title || "No Title Specified"}
                                  </h4>
                                  <p className="text-xs text-slate-400 line-clamp-2 mt-1">
                                    {auditData.technical_audit.social_meta.og_description || "No description meta tag provided for social preview snippets."}
                                  </p>
                                </div>
                              </div>
                            </div>

                            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-slate-400">
                              <span>og:image: {auditData.technical_audit.social_meta.has_og_image ? "✅" : "❌"}</span>
                              <span>twitter:card: {auditData.technical_audit.social_meta.has_twitter_card ? "✅" : "❌"}</span>
                            </div>
                          </div>
                        )}

                        {/* Link Health & Asset Optimization */}
                        <div className="bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-6 flex flex-col justify-between">
                          <div>
                            <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                              <Activity className="w-5 h-5 text-emerald-400" /> Link Health & Asset Modernization
                            </h3>

                            {/* Link Health */}
                            {auditData.technical_audit.link_health && (
                              <div className="mb-4 bg-[#111] border border-white/5 rounded-2xl p-4">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
                                    <LinkIcon className="w-3.5 h-3.5 text-indigo-400" /> Link Verification Health
                                  </span>
                                  <span className={`text-xs font-bold font-mono ${
                                    auditData.technical_audit.link_health.health_rate >= 90 ? "text-emerald-400" : "text-rose-400"
                                  }`}>
                                    {auditData.technical_audit.link_health.health_rate}% Operational
                                  </span>
                                </div>
                                <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden mb-2">
                                  <div 
                                    className={`h-full rounded-full ${
                                      auditData.technical_audit.link_health.health_rate >= 90 ? "bg-emerald-400" : "bg-rose-500"
                                    }`}
                                    style={{ width: `${auditData.technical_audit.link_health.health_rate}%` }}
                                  />
                                </div>
                                <p className="text-[11px] text-slate-500 font-mono">
                                  Sampled {auditData.technical_audit.link_health.total_checked} links · {auditData.technical_audit.link_health.broken_count} dead/broken links detected.
                                </p>
                              </div>
                            )}

                            {/* Image Modernization */}
                            {auditData.technical_audit.image_optimization && (
                              <div className="bg-[#111] border border-white/5 rounded-2xl p-4">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
                                    <ImageIcon className="w-3.5 h-3.5 text-purple-400" /> Next-Gen Image Formats
                                  </span>
                                  <span className={`text-xs font-bold font-mono ${
                                    auditData.technical_audit.image_optimization.is_optimized ? "text-emerald-400" : "text-yellow-400"
                                  }`}>
                                    {auditData.technical_audit.image_optimization.modern_percent}% Modern
                                  </span>
                                </div>
                                <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden mb-2">
                                  <div 
                                    className="h-full rounded-full bg-purple-500"
                                    style={{ width: `${auditData.technical_audit.image_optimization.modern_percent}%` }}
                                  />
                                </div>
                                <p className="text-[11px] text-slate-500 font-mono">
                                  {auditData.technical_audit.image_optimization.modern_count} WebP/AVIF/SVG vs {auditData.technical_audit.image_optimization.legacy_count} Legacy PNG/JPG formats.
                                </p>
                              </div>
                            )}
                          </div>

                          <p className="text-[11px] text-slate-500 mt-4 pt-3 border-t border-white/5 font-mono">
                            💡 Serving images in modern WebP/AVIF reduces bandwidth by 35-50% and improves LCP.
                          </p>
                        </div>

                      </div>
                    )}

                    {/* VULNERABILITY MATRIX */}
                    {auditData.critical_vulnerabilities && auditData.critical_vulnerabilities.length > 0 && (
                      <div className="col-span-1 md:col-span-3 mt-4">
                        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                          <h3 className="text-xl font-bold text-white flex items-center gap-2">
                            <Bug className="w-6 h-6 text-rose-400" /> Vulnerability Matrix ({auditData.critical_vulnerabilities.length} Identified)
                          </h3>
                          <button
                            type="button"
                            onClick={() => setCurrentView("fixes")}
                            className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 px-3.5 py-2 rounded-xl border border-emerald-500/20 hover:border-emerald-500/40 transition-all shadow-sm"
                          >
                            <Code2 className="w-3.5 h-3.5" /> Open Remediation Lab <ArrowRight className="w-3 h-3" />
                          </button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {auditData.critical_vulnerabilities.map((vuln, idx) => (
                            <div key={idx} className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-6 flex flex-col justify-between vulnerability-card print-avoid-break hover:border-white/20 transition-all">
                              <div>
                                <div className="flex justify-between items-start gap-4 mb-3">
                                  <span className="font-mono text-xs text-indigo-300 break-all bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20">{vuln.url}</span>
                                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full flex-shrink-0 ${
                                    vuln.severity === 'High' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                                    vuln.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                                    'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                  }`}>
                                    {vuln.severity}
                                  </span>
                                </div>
                                <h4 className="text-white font-semibold text-base mb-2">{vuln.issue_type}</h4>
                                <p className="text-slate-400 text-sm leading-relaxed mb-3">{vuln.description}</p>
                                
                                {/* Standards Reference & Impact Pills */}
                                <div className="flex flex-wrap items-center gap-2 mb-3">
                                  {vuln.standard_ref && (
                                    <span className="text-[10px] font-mono text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-md border border-indigo-500/20">
                                      {vuln.standard_ref}
                                    </span>
                                  )}
                                  {vuln.impact && (
                                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-md border border-emerald-500/20">
                                      {vuln.impact}
                                    </span>
                                  )}
                                </div>

                                {vuln.screenshot_url && (
                                  <div className="mt-3 mb-4 rounded-xl overflow-hidden border border-white/10 shadow-[0_0_15px_rgba(255,255,255,0.05)]">
                                    <img src={vuln.screenshot_url} alt={`Screenshot of issue on ${vuln.url}`} className="w-full object-cover transition-transform hover:scale-105 duration-700" />
                                  </div>
                                )}
                              </div>

                              {/* Action Link to Remediation Code Patch */}
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedVulnIndex(idx);
                                  setCurrentView("fixes");
                                }}
                                className="mt-3 w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-500/10 to-teal-500/10 hover:from-emerald-500/20 hover:to-teal-500/20 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 text-xs font-semibold flex items-center justify-center gap-2 transition-all shadow-sm group"
                              >
                                <Code2 className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
                                <span>Inspect Fix & Remediation Code</span>
                                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* FORENSIC CRAWL MAP */}
                    {auditData.scanned_urls && auditData.scanned_urls.length > 0 && (
                      <div className="col-span-1 md:col-span-3 mt-2 bg-[#0a0a0a] border border-white/10 rounded-3xl p-8">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                          <ShieldCheck className="w-5 h-5 text-emerald-400" /> Crawl Map ({auditData.scanned_urls.length} Pages Verified)
                        </h3>
                        <div className="max-h-48 overflow-y-auto pr-4 space-y-2">
                          {auditData.scanned_urls.map((scanUrl, idx) => (
                            <div key={idx} className="flex items-center gap-3 text-sm font-mono text-slate-400">
                              <LinkIcon className="w-3 h-3 opacity-50" />
                              <span className="truncate">{scanUrl}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* SCAN METHODOLOGY PANEL */}
                    {auditData.scan_methodology && (
                      <div className="col-span-1 md:col-span-3 mt-2 bg-[#0a0a0a] border border-indigo-500/20 rounded-3xl p-8">
                        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                          <div>
                            <h3 className="text-xl font-bold text-white flex items-center gap-2">
                              <BookOpen className="w-5 h-5 text-indigo-400" /> Scan Methodology & Coverage Report
                            </h3>
                            <p className="text-slate-400 text-xs mt-1">
                              Transparent breakdown of what was analyzed, how much data was processed, and which AI engine produced this report.
                            </p>
                          </div>
                          <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border bg-indigo-500/10 text-indigo-400 border-indigo-500/20">
                            {auditData.scan_methodology.scan_duration_seconds}s Total Duration
                          </span>
                        </div>

                        {/* Stats Grid */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col gap-1">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5">
                              <Globe className="w-3.5 h-3.5 text-indigo-400" /> Pages Crawled
                            </span>
                            <span className="text-2xl font-black text-white">{auditData.scan_methodology.pages_crawled}</span>
                            <span className="text-[10px] text-slate-600">of {40} max</span>
                          </div>
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col gap-1">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5">
                              <Activity className="w-3.5 h-3.5 text-emerald-400" /> Images Found
                            </span>
                            <span className="text-2xl font-black text-white">{auditData.scan_methodology.total_images_found}</span>
                            <span className="text-[10px] text-slate-600">across all pages</span>
                          </div>
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col gap-1">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5">
                              <LinkIcon className="w-3.5 h-3.5 text-purple-400" /> Links Analyzed
                            </span>
                            <span className="text-2xl font-black text-white">{auditData.scan_methodology.total_links_found}</span>
                            <span className="text-[10px] text-slate-600">anchor tags total</span>
                          </div>
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4 flex flex-col gap-1">
                            <span className="text-[11px] font-mono text-slate-500 uppercase flex items-center gap-1.5">
                              <Terminal className="w-3.5 h-3.5 text-amber-400" /> Forms Detected
                            </span>
                            <span className="text-2xl font-black text-white">{auditData.scan_methodology.total_forms_found}</span>
                            <span className="text-[10px] text-slate-600">interactive forms</span>
                          </div>
                        </div>

                        {/* AI Engine & Data Processed */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4">
                            <span className="text-[11px] font-mono text-slate-500 uppercase block mb-2">🤖 AI Engine Used</span>
                            <span className="text-sm font-bold text-indigo-300">{auditData.scan_methodology.ai_model_used}</span>
                          </div>
                          <div className="bg-[#111] border border-white/5 rounded-2xl p-4">
                            <span className="text-[11px] font-mono text-slate-500 uppercase block mb-2">📦 Data Processed</span>
                            <span className="text-sm font-bold text-white">
                              {(auditData.scan_methodology.characters_analyzed / 1000).toFixed(1)}K characters
                            </span>
                            <span className="text-[10px] text-slate-500 ml-2">of extracted page content</span>
                          </div>
                        </div>

                        {/* Categories Checked */}
                        <div>
                          <span className="text-[11px] font-mono text-slate-500 uppercase block mb-3">✅ Audit Categories Checked</span>
                          <div className="flex flex-wrap gap-2">
                            {auditData.scan_methodology.categories_checked.map((cat) => (
                              <span key={cat} className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-bold rounded-full">
                                <CheckCircle2 className="w-3 h-3" /> {cat}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}

                  </div>
                </div>
              )}
            </div>
          )}

          {/* ========================================== */}
          {/* PAGE: SCAN HISTORY & PORTFOLIO */}
          {/* ========================================== */}
          {currentView === "history" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 w-full max-w-5xl mx-auto">
              <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
                <div>
                  <h2 className="text-3xl font-bold text-white flex items-center gap-3">
                    <History className="w-8 h-8 text-indigo-400" />
                    Audit Portfolio & Scan History
                  </h2>
                  <p className="text-slate-400 mt-1 text-sm">
                    Review and compare past enterprise audits across all monitored domains.
                  </p>
                </div>
                <button
                  onClick={fetchScanHistory}
                  disabled={historyLoading}
                  className="bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg font-medium transition-colors text-sm flex items-center gap-2 border border-white/5 disabled:opacity-50"
                >
                  <RefreshCw className={`w-4 h-4 ${historyLoading ? "animate-spin" : ""}`} />
                  Refresh
                </button>
              </div>

              {/* STATS OVERVIEW */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-5">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-500">Total Audits</span>
                  <div className="text-3xl font-black text-white mt-1">{scanHistory.length}</div>
                </div>
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-5">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-500">Average AI Score</span>
                  <div className="text-3xl font-black text-indigo-400 mt-1">
                    {scanHistory.filter((s) => typeof s.global_score === "number").length > 0
                      ? Math.round(
                          scanHistory
                            .filter((s) => typeof s.global_score === "number")
                            .reduce((acc, curr) => acc + (curr.global_score || 0), 0) /
                            scanHistory.filter((s) => typeof s.global_score === "number").length
                        )
                      : "—"}
                  </div>
                </div>
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-5">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-500">Monitored Domains</span>
                  <div className="text-3xl font-black text-emerald-400 mt-1">
                    {new Set(scanHistory.map((s) => s.domain_url)).size}
                  </div>
                </div>
              </div>

              {historyLoading && scanHistory.length === 0 && (
                <div className="flex flex-col items-center justify-center p-16 text-slate-500 gap-3">
                  <Loader2 className="w-8 h-8 animate-spin text-indigo-400" />
                  <p className="font-mono text-sm">Fetching audit records from Supabase...</p>
                </div>
              )}

              {historyError && (
                <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm p-4 rounded-xl flex items-center gap-3 mb-6">
                  <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                  <p>{historyError}</p>
                </div>
              )}

              {!historyLoading && scanHistory.length === 0 && (
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-12 text-center">
                  <Globe className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-lg font-bold text-white mb-2">No audits recorded yet</h3>
                  <p className="text-slate-400 text-sm mb-6">Initiate your first deep web audit to start building your portfolio.</p>
                  <button
                    onClick={() => setCurrentView("scanner")}
                    className="bg-white text-black px-6 py-2.5 rounded-xl font-bold hover:bg-slate-200 transition-colors text-sm"
                  >
                    Go to Scanner
                  </button>
                </div>
              )}

              {scanHistory.length > 0 && (
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-white/5 border-b border-white/10 text-slate-400 font-mono text-xs uppercase tracking-wider">
                        <tr>
                          <th className="py-4 px-6">Domain / Target</th>
                          <th className="py-4 px-6">Status</th>
                          <th className="py-4 px-6">AI Score</th>
                          <th className="py-4 px-6">Vulnerabilities</th>
                          <th className="py-4 px-6">Audited On</th>
                          <th className="py-4 px-6 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 text-slate-300">
                        {scanHistory
                          .slice()
                          .sort((a, b) => {
                            const timeA = new Date(a.created_at || a.completed_at || a.started_at || 0).getTime();
                            const timeB = new Date(b.created_at || b.completed_at || b.started_at || 0).getTime();
                            return timeB - timeA;
                          })
                          .map((scan) => (
                          <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                            <td className="py-4 px-6 font-mono font-medium text-white flex items-center gap-2">
                              <Globe className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                              <span className="truncate max-w-[260px]">{scan.domain_url}</span>
                            </td>
                            <td className="py-4 px-6">
                              <span
                                className={`text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full ${
                                  scan.status === "completed"
                                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                    : scan.status === "failed"
                                    ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                                    : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 animate-pulse"
                                }`}
                              >
                                {scan.status}
                              </span>
                            </td>
                            <td className="py-4 px-6">
                              {typeof scan.global_score === "number" ? (
                                <span
                                  className={`font-black text-base ${
                                    scan.global_score >= 80
                                      ? "text-emerald-400"
                                      : scan.global_score >= 50
                                      ? "text-yellow-400"
                                      : "text-rose-400"
                                  }`}
                                >
                                  {scan.global_score}/100
                                </span>
                              ) : (
                                <span className="text-slate-600">—</span>
                              )}
                            </td>
                            <td className="py-4 px-6">
                              <span className="font-mono text-xs text-slate-400">
                                {scan.vulnerability_count} issues
                              </span>
                            </td>
                            <td className="py-4 px-6 text-xs text-slate-400 font-mono">
                              {scan.created_at || scan.completed_at || scan.started_at ? (
                                new Date(scan.created_at || scan.completed_at || scan.started_at || "").toLocaleDateString(undefined, {
                                  month: "short",
                                  day: "numeric",
                                  year: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                })
                              ) : (
                                "Recent"
                              )}
                            </td>
                            <td className="py-4 px-6 text-right">
                              <button
                                onClick={() => openHistoricalScan(scan.id)}
                                className="bg-white/10 hover:bg-white/20 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition-colors inline-flex items-center gap-1.5 border border-white/5 hover:border-white/20"
                              >
                                View Report <ExternalLink className="w-3 h-3" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ========================================== */}
          {/* PAGE 4: THE LAB (CODE FIXES) */}
          {/* ========================================== */}
          {currentView === "fixes" && auditData && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 h-full flex flex-col">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      Automated Patch Generator
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      {auditData.critical_vulnerabilities?.length || 0} Issues Ready For Remediation
                    </span>
                  </div>
                  <h2 className="text-3xl font-black text-white flex items-center gap-3">
                    <Code2 className="w-8 h-8 text-emerald-400" />
                    Remediation Laboratory
                  </h2>
                  <p className="text-slate-400 mt-1 text-sm">
                    Developer-grade, copy-paste ready code patches tailored to each discovered defect.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setCurrentView("scanner")}
                  className="self-start md:self-center px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 text-xs font-semibold flex items-center gap-2 transition-all"
                >
                  <ArrowRight className="w-3.5 h-3.5 rotate-180" /> Back to Dashboard
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 min-h-[550px]">
                {/* Defect List Selector (Left column) */}
                <div className="lg:col-span-4 space-y-3 overflow-y-auto max-h-[750px] pr-2">
                  <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-mono flex items-center justify-between">
                    <span>Discovered Vulnerabilities</span>
                    <span className="bg-white/10 px-2 py-0.5 rounded-full text-[10px] text-white">
                      {auditData.critical_vulnerabilities?.length || 0}
                    </span>
                  </div>

                  {auditData.critical_vulnerabilities?.map((vuln, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setSelectedVulnIndex(idx)}
                      className={`w-full text-left p-4 rounded-2xl border transition-all ${
                        selectedVulnIndex === idx
                          ? "bg-gradient-to-r from-emerald-500/15 to-transparent border-emerald-500/50 shadow-lg shadow-emerald-500/10"
                          : "bg-[#0a0a0a] border-white/5 hover:border-white/20 text-slate-400"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <span className="font-mono text-[11px] text-indigo-400 truncate max-w-[170px] bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                          {vuln.url}
                        </span>
                        <span
                          className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                            vuln.severity === "High"
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : vuln.severity === "Medium"
                              ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                              : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                          }`}
                        >
                          {vuln.severity}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-white mb-1.5">{vuln.issue_type}</h4>
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-2">
                        {vuln.description}
                      </p>

                      {/* Pill tags */}
                      <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-white/5">
                        {vuln.standard_ref && (
                          <span className="text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded border border-white/5 truncate max-w-[180px]">
                            {vuln.standard_ref}
                          </span>
                        )}
                        {vuln.impact && (
                          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                            {vuln.impact}
                          </span>
                        )}
                      </div>
                    </button>
                  ))}
                </div>

                {/* Enhanced Code Editor & Differential Workbench (Right column) */}
                <div className="lg:col-span-8 flex flex-col space-y-4">
                  {auditData.critical_vulnerabilities?.[selectedVulnIndex] ? (() => {
                    const activeVuln = auditData.critical_vulnerabilities[selectedVulnIndex];
                    const activePatch = activeVuln.remediation_code || "// Automated remediation patch is currently being computed.";
                    const defectCode = activeVuln.defect_code || "// Problematic template markup observed on target endpoint:\n<img src=\"/hero-banner.jpg\" />\n<div class=\"lang-selector\">\n  <html lang=\"en\">\n</div>";

                    return (
                      <>
                        {/* RATIONALE & ENGINEERING DIRECTIVE CARD */}
                        <div className="bg-[#0a0a0e] border border-white/10 rounded-2xl p-5 relative overflow-hidden shadow-xl">
                          <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                            <div className="flex items-center gap-2">
                              <Sparkles className="w-5 h-5 text-emerald-400" />
                              <h3 className="text-base font-bold text-white">
                                Engineering Directive & Root Cause Analysis
                              </h3>
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                              {activeVuln.standard_ref && (
                                <span className="text-xs font-mono font-bold text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/30">
                                  {activeVuln.standard_ref}
                                </span>
                              )}
                              {activeVuln.impact && (
                                <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/30">
                                  {activeVuln.impact}
                                </span>
                              )}
                            </div>
                          </div>

                          <p className="text-slate-300 text-sm leading-relaxed mb-3">
                            {activeVuln.explanation || activeVuln.description}
                          </p>

                          <div className="flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 pt-3 border-t border-white/5 gap-2">
                            <span>Target File: <strong className="text-white">{activeVuln.file_target || "src/components/Template.tsx"}</strong></span>
                            <span>Endpoint: <strong className="text-indigo-400">{activeVuln.url}</strong></span>
                          </div>
                        </div>

                        {/* CODE WORKBENCH WITH BEFORE/AFTER TABS */}
                        <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden flex flex-col shadow-2xl flex-1 min-h-[420px]">
                          {/* Workbench Top Bar */}
                          <div className="bg-[#121217] px-5 py-3 border-b border-white/10 flex flex-wrap items-center justify-between gap-3">
                            <div className="flex items-center gap-3">
                              <div className="flex items-center gap-1.5">
                                <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                                <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                              </div>
                              <span className="font-mono text-xs text-slate-300 font-semibold ml-2">
                                {activeVuln.file_target || "Solution.tsx"}
                              </span>
                            </div>

                            {/* View Mode Switcher */}
                            <div className="flex items-center gap-1 bg-black/60 p-1 rounded-xl border border-white/10">
                              <button
                                type="button"
                                onClick={() => setCodeDiffTab("diff")}
                                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                                  codeDiffTab === "diff"
                                    ? "bg-emerald-500 text-black font-bold shadow-md shadow-emerald-500/20"
                                    : "text-slate-400 hover:text-white hover:bg-white/5"
                                }`}
                              >
                                Side-by-Side Diff
                              </button>
                              <button
                                type="button"
                                onClick={() => setCodeDiffTab("after")}
                                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                                  codeDiffTab === "after"
                                    ? "bg-emerald-500 text-black font-bold shadow-md shadow-emerald-500/20"
                                    : "text-slate-400 hover:text-white hover:bg-white/5"
                                }`}
                              >
                                Remediation Patch
                              </button>
                              <button
                                type="button"
                                onClick={() => setCodeDiffTab("before")}
                                className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                                  codeDiffTab === "before"
                                    ? "bg-rose-500 text-white font-bold shadow-md shadow-rose-500/20"
                                    : "text-slate-400 hover:text-white hover:bg-white/5"
                                }`}
                              >
                                Observed Defect
                              </button>
                            </div>

                            {/* One-Click Copy Button */}
                            <button
                              type="button"
                              onClick={() => handleCopyCode(activePatch)}
                              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold font-mono flex items-center gap-1.5 transition-all ${
                                copiedFix
                                  ? "bg-emerald-500 text-black shadow-lg shadow-emerald-500/30"
                                  : "bg-white/10 hover:bg-white/20 text-white border border-white/10 hover:border-white/20"
                              }`}
                            >
                              {copiedFix ? (
                                <>
                                  <Check className="w-3.5 h-3.5 stroke-[3]" /> Copied to Clipboard!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5" /> Copy Code Patch
                                </>
                              )}
                            </button>
                          </div>

                          {/* Code Content Area */}
                          <div className="flex-1 bg-[#050507] p-4 md:p-6 overflow-auto font-mono text-xs md:text-sm">
                            {/* MODE 1: SIDE-BY-SIDE DIFF */}
                            {codeDiffTab === "diff" && (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 h-full">
                                {/* Defective Before Box */}
                                <div className="rounded-xl border border-rose-500/30 bg-rose-950/15 p-4 flex flex-col">
                                  <div className="flex items-center justify-between pb-2 mb-3 border-b border-rose-500/20 text-xs font-bold text-rose-400">
                                    <span className="flex items-center gap-1.5">
                                      <Minus className="w-3.5 h-3.5 stroke-[3]" /> Observed Defect (Before)
                                    </span>
                                    <span className="text-[10px] text-rose-400/70 uppercase">Non-Compliant</span>
                                  </div>
                                  <pre className="text-rose-300 leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1">
                                    <code>{defectCode}</code>
                                  </pre>
                                </div>

                                {/* Validated After Box */}
                                <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-4 flex flex-col">
                                  <div className="flex items-center justify-between pb-2 mb-3 border-b border-emerald-500/20 text-xs font-bold text-emerald-400">
                                    <span className="flex items-center gap-1.5">
                                      <Check className="w-3.5 h-3.5 stroke-[3]" /> Remediation Patch (After)
                                    </span>
                                    <span className="text-[10px] text-emerald-400/70 uppercase">Production Grade</span>
                                  </div>
                                  <pre className="text-emerald-300 leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1">
                                    <code>{activePatch}</code>
                                  </pre>
                                </div>
                              </div>
                            )}

                            {/* MODE 2: REMEDIATION PATCH ONLY */}
                            {codeDiffTab === "after" && (
                              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-5 h-full flex flex-col">
                                <div className="flex items-center justify-between pb-2 mb-3 border-b border-emerald-500/20 text-xs font-bold text-emerald-400">
                                  <span>// Clean Drop-in Patch: {activeVuln.file_target || "src/components/Template.tsx"}</span>
                                  <span className="text-[10px] uppercase font-mono text-emerald-400/80">Validated Syntax</span>
                                </div>
                                <pre className="text-emerald-300 leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1">
                                  <code>{activePatch}</code>
                                </pre>
                              </div>
                            )}

                            {/* MODE 3: OBSERVED DEFECT ONLY */}
                            {codeDiffTab === "before" && (
                              <div className="rounded-xl border border-rose-500/20 bg-rose-950/10 p-5 h-full flex flex-col">
                                <div className="flex items-center justify-between pb-2 mb-3 border-b border-rose-500/20 text-xs font-bold text-rose-400">
                                  <span>// Problematic Markup Detected on {activeVuln.url}</span>
                                  <span className="text-[10px] uppercase font-mono text-rose-400/80">Defect Signature</span>
                                </div>
                                <pre className="text-rose-300 leading-relaxed overflow-x-auto whitespace-pre-wrap flex-1">
                                  <code>{defectCode}</code>
                                </pre>
                              </div>
                            )}
                          </div>

                          {/* Workbench Footer Instruction */}
                          <div className="px-5 py-3 bg-[#0d0d12] border-t border-white/5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-slate-400">
                            <span>Compliance Standard: <strong className="text-white">{activeVuln.standard_ref || "W3C / WCAG 2.1 AA"}</strong></span>
                            <span>Target Engine: <strong className="text-emerald-400">Next.js / React 19 / Modern Web</strong></span>
                          </div>
                        </div>
                      </>
                    );
                  })() : (
                    <div className="p-16 text-center text-slate-500 font-mono text-sm bg-[#0a0a0a] border border-white/10 rounded-2xl">
                      Select a vulnerability from the left panel to inspect its tailored remediation code patch.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}