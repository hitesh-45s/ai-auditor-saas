"use client";

import { useState, useEffect } from "react";
import { createClient } from "@supabase/supabase-js";
import { Search, Activity, Globe, Terminal, AlertTriangle, Code2, Loader2, ArrowRight, Bug, Link as LinkIcon, ShieldCheck, LogOut, BookOpen, Home as HomeIcon, Lock, Mail, CheckCircle2 } from "lucide-react";

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
};

type AuditResult = {
  global_score: number;
  executive_summary: string;
  top_global_issue: string;
  critical_vulnerabilities?: Vulnerability[];
  scanned_urls?: string[];
};

export default function App() {
  // --- GLOBAL STATE ---
  const [session, setSession] = useState<any>(null);
  const [currentView, setCurrentView] = useState<"login" | "home" | "scanner" | "fixes">("login");
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
  
  // --- REMEDIATION LAB STATE ---
  const [selectedVulnIndex, setSelectedVulnIndex] = useState(0);

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
              setScanError("The scan failed on the server. Check the worker logs and try again.");
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
    e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const { error } = await supabase.auth.signUp({ email, password });
    if (error) setAuthError(error.message);
    else alert("Success! Please check your email to verify your account (if email confirmation is enabled in Supabase). Or try logging in.");
    setAuthLoading(false);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
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
  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || !session?.user?.id) return;

    setIsScanning(true);
    setScanId(null);
    setScanStatus("pending");
    setAuditData(null);
    setScanError(null);
    setScreenshotUrl(null);

    try {
      // NEW: Send the JWT Token in the Authorization header
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "Authorization": `Bearer ${session.access_token}`
        },
        body: JSON.stringify({
          url: url.startsWith("http") ? url : `https://${url}`,
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
    <div className="min-h-screen bg-[#050505] flex text-white overflow-hidden">
      
      {/* SIDEBAR NAVIGATION */}
      <aside className="w-64 border-r border-white/5 bg-[#0a0a0a] flex flex-col z-20 relative">
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
      <main className="flex-1 relative overflow-y-auto">
        {/* Background Gradients */}
        <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-b from-indigo-900/10 to-transparent pointer-events-none"></div>
        
        <div className="p-8 max-w-6xl mx-auto min-h-full">
          
          {/* ========================================== */}
          {/* PAGE 2: HOME & INSTRUCTIONS VIEW */}
          {/* ========================================== */}
          {currentView === "home" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h1 className="text-4xl font-extrabold mb-2">Welcome to the Engine Room.</h1>
              <p className="text-slate-400 text-lg mb-12">The world's most aggressive, AI-powered web auditing architecture.</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-6">
                  <div className="w-10 h-10 rounded-lg bg-indigo-500/20 flex items-center justify-center mb-4">
                    <Globe className="w-5 h-5 text-indigo-400" />
                  </div>
                  <h3 className="text-xl font-bold mb-2">1. Deep Crawling</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    Our Python workers bypass WAFs and recursively spider up to 50 pages of the target infrastructure, extracting raw DOM geometry and text.
                  </p>
                </div>
                <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-6">
                  <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center mb-4">
                    <Terminal className="w-5 h-5 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-bold mb-2">2. Granular Pinpointing</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    We don't just guess. The Gemini model ingests the entire crawl data and pinpoints the exact URL and severity of every SEO and React bug.
                  </p>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-2xl p-8">
                <h3 className="text-lg font-bold flex items-center gap-2 mb-4">
                  <BookOpen className="w-5 h-5 text-emerald-400" /> Rules of Engagement
                </h3>
                <ul className="space-y-4 text-slate-300 text-sm">
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                    <p><strong className="text-white">Asynchronous Execution:</strong> The python workers will crawl the target domain asynchronously, retrieving results efficiently.</p>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                    <p><strong className="text-white">Visual Feedback:</strong> As soon as the crawl begins, a screenshot of the target will be uploaded and displayed on your dashboard.</p>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                    <p><strong className="text-white">Remediation:</strong> Once a scan completes, the "Remediation Code" tab will unlock, providing you with drop-in React code to fix the primary issue.</p>
                  </li>
                </ul>
                <button 
                  onClick={startNewScan}
                  className="mt-8 bg-white text-black px-6 py-3 rounded-xl font-bold hover:bg-slate-200 transition-colors flex items-center gap-2"
                >
                  Initiate New Scan <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* ========================================== */}
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
                  
                  {/* DASHBOARD HEADER & RESET BUTTON */}
                  <div className="flex items-center justify-between mb-8">
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                      <Activity className="w-6 h-6 text-indigo-400" /> Audit Complete
                    </h2>
                    <button 
                      onClick={startNewScan}
                      className="bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg font-medium transition-colors text-sm flex items-center gap-2 border border-white/5"
                    >
                      <Search className="w-4 h-4" /> Run New Scan
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* SCORE & SCREENSHOT */}
                    <div className="col-span-1 bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8 flex flex-col items-center justify-center relative overflow-hidden group">
                      <div className="text-sm font-bold tracking-widest text-slate-500 uppercase mb-6 z-10 bg-black/50 px-3 py-1 rounded-full">Global AI Score</div>
                      
                      <div className={`relative flex items-center justify-center w-40 h-40 rounded-full border-4 mb-6 z-10 bg-[#0a0a0a] ${
                        auditData.global_score >= 80 ? "border-emerald-500/30 text-emerald-400" : 
                        auditData.global_score >= 50 ? "border-yellow-500/30 text-yellow-400" : "border-rose-500/30 text-rose-400"
                      }`}>
                        <span className="text-5xl font-black">{auditData.global_score}</span>
                      </div>

                      {/* NEW: Display the screenshot behind the score or below it! */}
                      {screenshotUrl && (
                          <div className="w-full mt-4 rounded-xl overflow-hidden border border-white/10 shadow-[0_0_15px_rgba(255,255,255,0.05)] relative z-10">
                              <img src={screenshotUrl} alt="Target Website" className="w-full object-cover transition-transform hover:scale-105 duration-700" />
                          </div>
                      )}
                    </div>

                    {/* SUMMARY */}
                    <div className="col-span-1 md:col-span-2 flex flex-col gap-6">
                      <div className="bg-[#0a0a0a]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8">
                        <h3 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
                          <Terminal className="w-5 h-5 text-indigo-400" /> Executive Summary
                        </h3>
                        <p className="text-slate-300 leading-relaxed text-lg">{auditData.executive_summary}</p>
                      </div>
                      <div className="bg-rose-500/5 border border-rose-500/10 rounded-3xl p-8">
                        <h3 className="text-lg font-bold text-rose-400 mb-3 flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5" /> Top Global Issue
                        </h3>
                        <p className="text-slate-300 leading-relaxed">{auditData.top_global_issue}</p>
                      </div>
                    </div>

                    {/* VULNERABILITY MATRIX */}
                    {auditData.critical_vulnerabilities && auditData.critical_vulnerabilities.length > 0 && (
                      <div className="col-span-1 md:col-span-3 mt-4">
                        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                          <Bug className="w-6 h-6 text-rose-400" /> Vulnerability Matrix
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {auditData.critical_vulnerabilities.map((vuln, idx) => (
                            <div key={idx} className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-6 flex flex-col">
                              <div className="flex justify-between items-start gap-4 mb-3">
                                <span className="font-mono text-xs text-indigo-300 break-all bg-indigo-500/10 px-2 py-1 rounded border border-indigo-500/20">{vuln.url}</span>
                                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-full ${
                                  vuln.severity === 'High' ? 'bg-rose-500/20 text-rose-400' :
                                  vuln.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                  'bg-blue-500/20 text-blue-400'
                                }`}>
                                  {vuln.severity}
                                </span>
                              </div>
                              <h4 className="text-white font-semibold mb-2">{vuln.issue_type}</h4>
                              <p className="text-slate-400 text-sm leading-relaxed">{vuln.description}</p>
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
              <div>
                <h2 className="text-3xl font-bold text-white flex items-center gap-3">
                  <Code2 className="w-8 h-8 text-emerald-400" />
                  Remediation Laboratory
                </h2>
                <p className="text-slate-400 mt-1 text-sm mb-6">
                  Select a discovered defect to inspect its targeted, page-specific React patch.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-[500px]">
                {/* Defect List Selector */}
                <div className="space-y-3 lg:col-span-1 overflow-y-auto max-h-[600px] pr-2">
                  {auditData.critical_vulnerabilities?.map((vuln, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setSelectedVulnIndex(idx)}
                      className={`w-full text-left p-4 rounded-xl border transition-all ${
                        selectedVulnIndex === idx
                          ? "bg-white/10 border-emerald-500/50 shadow-lg shadow-emerald-500/10"
                          : "bg-[#0a0a0a] border-white/5 hover:border-white/20 text-slate-400"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <span className="font-mono text-[11px] text-indigo-400 truncate max-w-[180px]">
                          {vuln.url}
                        </span>
                        <span
                          className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                            vuln.severity === "High"
                              ? "bg-rose-500/20 text-rose-400"
                              : vuln.severity === "Medium"
                              ? "bg-yellow-500/20 text-yellow-400"
                              : "bg-blue-500/20 text-blue-400"
                          }`}
                        >
                          {vuln.severity}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-white mb-1">{vuln.issue_type}</h4>
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                        {vuln.description}
                      </p>
                    </button>
                  ))}
                </div>

                {/* Code Editor Preview */}
                <div className="lg:col-span-2 bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden flex flex-col shadow-2xl">
                  {auditData.critical_vulnerabilities?.[selectedVulnIndex] ? (
                    <>
                      <div className="bg-[#111] px-5 py-3 border-b border-white/10 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-rose-500" />
                          <div className="w-3 h-3 rounded-full bg-yellow-500" />
                          <div className="w-3 h-3 rounded-full bg-emerald-500" />
                          <span className="font-mono text-xs text-slate-300 ml-3">
                            {auditData.critical_vulnerabilities[selectedVulnIndex].file_target || "Solution.tsx"}
                          </span>
                        </div>
                        <span className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded border border-indigo-500/20 truncate max-w-[280px]">
                          {auditData.critical_vulnerabilities[selectedVulnIndex].url}
                        </span>
                      </div>

                      <div className="p-6 overflow-auto flex-1 bg-[#050505]">
                        <pre className="font-mono text-xs md:text-sm text-emerald-400/90 leading-relaxed whitespace-pre-wrap">
                          <code>
                            {auditData.critical_vulnerabilities[selectedVulnIndex].remediation_code ||
                              "// No automated patch available for this vulnerability."}
                          </code>
                        </pre>
                      </div>
                    </>
                  ) : (
                    <div className="p-10 text-center text-slate-500 font-mono text-sm">
                      Select a vulnerability from the list to view its code patch.
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