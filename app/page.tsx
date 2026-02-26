'use client';

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Search, Loader2, ShieldAlert, Server, Activity, Globe, ChevronRight, Sparkles, List, History, X, Clock, Calendar, Info, Filter, Languages, Terminal } from 'lucide-react';
import { GoogleGenAI } from '@google/genai';
import Markdown from 'react-markdown';
import { motion, AnimatePresence } from 'motion/react';

interface SubdomainItem {
  host: string;
  ip: string | null;
  statusCode?: number | null;
}

interface WhoisInfo {
  domain?: string;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
}

interface ScanHistory {
  id: string;
  domain: string;
  date: string;
  count: number;
  mode: 'standard' | 'ai';
  subdomains: SubdomainItem[];
  analysis?: string;
  whois?: WhoisInfo;
  notes?: string;
}

export default function Page() {
  const [domain, setDomain] = useState('');
  const [mode, setMode] = useState<'standard' | 'ai'>('ai');
  const [language, setLanguage] = useState('English');
  const [isScanning, setIsScanning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [subdomains, setSubdomains] = useState<SubdomainItem[]>([]);
  const [analysis, setAnalysis] = useState<string>('');
  const [whois, setWhois] = useState<WhoisInfo | null>(null);
  const [error, setError] = useState<string>('');
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [filterText, setFilterText] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [bytesReceived, setBytesReceived] = useState(0);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!isScanning && !isAnalyzing) return;

    const randomLines = [
      `[*] Bypassing WAF...`,
      `[*] Injecting payloads...`,
      `[+] Enumerating DNS records...`,
      `[*] Checking zone transfers...`,
      `[+] Parsing certificate transparency logs...`,
      `[*] Querying WayBackMachine...`,
      `[!] Rate limit detected, sleeping for 200ms...`,
      `[*] Brute-forcing common subdomains...`,
      `[+] Found wildcard record...`,
      `[*] Resolving CNAMEs...`,
      `[*] Analyzing HTTP headers...`,
      `[+] Extracting metadata...`
    ];

    const interval = setInterval(() => {
      if (Math.random() > 0.6) {
        const randomLine = randomLines[Math.floor(Math.random() * randomLines.length)];
        setTerminalLines(prev => [...prev, randomLine].slice(-100));
      }
    }, 600);

    return () => clearInterval(interval);
  }, [isScanning, isAnalyzing]);

  useEffect(() => {
    if (isScanning || isAnalyzing) {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLines, isScanning, isAnalyzing]);

  const filteredSubdomains = useMemo(() => {
    return subdomains.filter(sub => {
      const matchesText = sub.host.includes(filterText.toLowerCase()) || (sub.ip && sub.ip.includes(filterText));
      let matchesStatus = true;
      if (filterStatus === 'resolvable') matchesStatus = !!sub.ip;
      if (filterStatus === 'unresolvable') matchesStatus = !sub.ip;
      if (filterStatus === 'active') matchesStatus = !!sub.statusCode && sub.statusCode >= 200 && sub.statusCode < 400;
      if (filterStatus === 'error') matchesStatus = !!sub.statusCode && sub.statusCode >= 400;
      return matchesText && matchesStatus;
    });
  }, [subdomains, filterText, filterStatus]);

  useEffect(() => {
    const saved = localStorage.getItem('subfinder_history');
    if (saved) {
      try {
        setHistory(JSON.parse(saved));
      } catch (e) {}
    }
  }, []);

  const saveHistory = (foundSubdomains: SubdomainItem[], analysisStr?: string, whoisData?: WhoisInfo) => {
    setHistory(prev => {
      const newScan: ScanHistory = {
        id: Date.now().toString(),
        domain,
        date: new Date().toISOString(),
        count: foundSubdomains.length,
        mode,
        subdomains: foundSubdomains,
        analysis: analysisStr,
        whois: whoisData || undefined,
      };
      const updated = [newScan, ...prev].slice(0, 50);
      localStorage.setItem('subfinder_history', JSON.stringify(updated));
      return updated;
    });
  };

  const loadHistoryItem = (item: ScanHistory) => {
    setDomain(item.domain);
    setMode(item.mode);
    setFilterText('');
    setFilterStatus('all');
    
    // Handle legacy history items where subdomains was string[]
    const loadedSubdomains = item.subdomains.map(sub => 
      typeof sub === 'string' ? { host: sub, ip: null, statusCode: null } : sub
    );
    
    setSubdomains(loadedSubdomains);
    setAnalysis(item.analysis || '');
    setWhois(item.whois || null);
    setError('');
    setShowHistory(false);
  };

  const updateHistoryNote = (id: string, notes: string) => {
    setHistory(prev => {
      const updated = prev.map(item => item.id === id ? { ...item, notes } : item);
      localStorage.setItem('subfinder_history', JSON.stringify(updated));
      return updated;
    });
  };

  const handleStop = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;

    // Basic domain validation (allow multiple dots for .co.uk, subdomains, etc.)
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Please enter a valid domain (e.g., example.com or example.co.id)');
      return;
    }

    setError('');
    setSubdomains([]);
    setAnalysis('');
    setWhois(null);
    setFilterText('');
    setFilterStatus('all');
    setIsScanning(true);
    setBytesReceived(0);
    setTerminalLines([`root@kali:~# subfinder -d ${domain} -all`, `[*] Initializing engine...`, `[*] Fetching from Github...`]);

    let whoisData: WhoisInfo | null = null;
    let foundSubdomains: SubdomainItem[] = [];

    abortControllerRef.current = new AbortController();

    try {
      // 0. Fetch WHOIS in background
      fetch(`/api/whois?domain=${encodeURIComponent(domain)}`, { signal: abortControllerRef.current.signal })
        .then(res => res.json())
        .then(data => {
          if (data && data.whois) {
            whoisData = data.whois;
            setWhois(data.whois);
          }
        })
        .catch(err => {
          if (err.name !== 'AbortError') console.error("Failed to fetch WHOIS", err);
        });

      // 1. Fetch subdomains via SSE
      const res = await fetch(`/api/subdomains?domain=${encodeURIComponent(domain)}`, {
        signal: abortControllerRef.current.signal
      });
      
      if (!res.ok) {
        throw new Error('Failed to start scan');
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error('Failed to read response');

      const decoder = new TextDecoder();
      let isDone = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        if (value) {
          setBytesReceived(prev => prev + value.length);
        }

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6);
            if (!dataStr) continue;
            try {
              const data = JSON.parse(dataStr);
              if (data.error) {
                throw new Error(data.error);
              }
              if (data.subdomains) {
                foundSubdomains = [...foundSubdomains, ...data.subdomains];
                setSubdomains(prev => {
                  // Ensure no duplicates in state just in case
                  const existingHosts = new Set(prev.map(s => s.host));
                  const newUnique = data.subdomains.filter((s: SubdomainItem) => !existingHosts.has(s.host));
                  
                  if (newUnique.length > 0) {
                    setTerminalLines(lines => {
                      const newLines = [...lines];
                      newUnique.forEach((s: SubdomainItem) => {
                        newLines.push(`[+] Discovered: ${s.host} ${s.ip ? `[${s.ip}]` : ''}`);
                      });
                      return newLines.slice(-100);
                    });
                  }

                  return [...prev, ...newUnique];
                });
              }
              if (data.done) {
                isDone = true;
              }
            } catch (e) {
              // Ignore parse errors for incomplete chunks
            }
          }
        }
      }

      setIsScanning(false);

      if (foundSubdomains.length === 0) {
        setError('No subdomains found for this domain.');
        return;
      }

      if (mode === 'standard') {
        setTerminalLines(prev => [...prev, `[*] Scan complete. Found ${foundSubdomains.length} subdomains.`].slice(-100));
        saveHistory(foundSubdomains, undefined, whoisData || undefined);
        return;
      }

      // 2. Analyze with AI
      setIsAnalyzing(true);
      setTerminalLines(prev => [...prev, `[*] Scan complete. Found ${foundSubdomains.length} subdomains.`, `[*] Initiating Gemini AI analysis module...`, `[*] Streaming data to AI...`].slice(-100));
      
      const ai = new GoogleGenAI({ apiKey: process.env.NEXT_PUBLIC_GEMINI_API_KEY });
      
      const prompt = `
You are an expert cybersecurity analyst and infrastructure architect.
I have performed a subdomain enumeration on the domain "${domain}".
Here are the discovered subdomains (${foundSubdomains.length} total):

${foundSubdomains.slice(0, 500).map(s => `${s.host} ${s.ip ? `(IP: ${s.ip})` : ''}`).join('\n')}
${foundSubdomains.length > 500 ? '\n... (truncated for length)' : ''}

Please provide a comprehensive analysis of these subdomains:
1. **Categorization**: Group them by likely purpose (e.g., Production, Staging/Dev, Internal/Admin, Marketing, Mail, etc.).
2. **Security Posture**: Identify any potentially sensitive or vulnerable exposures (e.g., exposed dev environments, admin panels, old versions).
3. **Infrastructure Insights**: What can we infer about their tech stack or infrastructure setup based on these names and IPs?
4. **Recommendations**: Brief actionable advice for the security team.

Format the response in clean Markdown. Use headings, bullet points, and bold text for readability. Keep it professional and concise.
IMPORTANT: You MUST write your entire response in ${language}.
      `;

      const response = await ai.models.generateContentStream({
        model: 'gemini-3-flash-preview',
        contents: prompt,
      });

      let fullAnalysis = '';
      for await (const chunk of response) {
        if (chunk.text) {
          fullAnalysis += chunk.text;
          setAnalysis(fullAnalysis);
        }
      }

      saveHistory(foundSubdomains, fullAnalysis, whoisData || undefined);

    } catch (err: any) {
      if (err.name === 'AbortError') {
        setTerminalLines(prev => [...prev, `[!] Scan aborted by user.`].slice(-100));
        if (foundSubdomains.length > 0) {
          saveHistory(foundSubdomains, undefined, whoisData || undefined);
        }
        return;
      }
      console.error(err);
      setError(err.message || 'An error occurred during the scan.');
    } finally {
      setIsScanning(false);
      setIsAnalyzing(false);
      abortControllerRef.current = null;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-12 flex flex-col gap-8">
      {/* Header */}
      <header className="flex flex-col gap-4 items-center text-center relative">
        <div className="absolute top-0 right-0">
          <button
            onClick={() => setShowHistory(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#141414] border border-white/10 rounded-full hover:bg-white/5 transition-colors text-sm text-gray-400 hover:text-white"
          >
            <History className="w-4 h-4" />
            History
          </button>
        </div>
        <div className="inline-flex items-center justify-center p-3 bg-emerald-500/10 rounded-2xl mb-2 mt-8 md:mt-0">
          <Activity className="w-8 h-8 text-emerald-400" />
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
          Subfinder AI By <span className="text-emerald-400">ARNDOZ</span>
        </h1>
        <p className="text-gray-400 max-w-2xl text-lg">
          Discover subdomains and instantly analyze infrastructure patterns, security posture, and exposed environments using Gemini AI.
        </p>
      </header>

      {/* Search Form */}
      <div className="w-full max-w-2xl mx-auto flex flex-col gap-6">
        <form onSubmit={handleScan} className="relative group w-full">
          <div className="absolute inset-0 bg-emerald-500/20 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <div className="relative flex items-center bg-[#141414] border border-white/10 rounded-full p-2 shadow-2xl">
            <div className="pl-4 pr-2 text-gray-500">
              <Globe className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="flex-1 bg-transparent border-none outline-none text-white placeholder:text-gray-600 px-2 py-3 text-lg font-mono"
              disabled={isScanning || isAnalyzing}
            />
            {isScanning ? (
              <button
                type="button"
                onClick={handleStop}
                className="bg-red-500 hover:bg-red-400 text-black font-semibold px-6 py-3 rounded-full transition-colors flex items-center gap-2"
              >
                <X className="w-5 h-5" />
                Stop
              </button>
            ) : isAnalyzing ? (
              <button
                type="button"
                disabled
                className="bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-6 py-3 rounded-full transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Loader2 className="w-5 h-5 animate-spin" />
                Analyzing
              </button>
            ) : (
              <button
                type="submit"
                disabled={!domain}
                className="bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-6 py-3 rounded-full transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Search className="w-5 h-5" />
                {mode === 'ai' ? 'Analyze' : 'Search'}
              </button>
            )}
          </div>
        </form>

        {/* Terminal Progress Indicator */}
        <AnimatePresence>
          {(isScanning || isAnalyzing) && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="w-full max-w-2xl mx-auto overflow-hidden"
            >
              <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-4 font-mono text-xs sm:text-sm text-emerald-500 h-48 overflow-y-auto custom-scrollbar shadow-2xl flex flex-col">
                <div className="flex items-center justify-between mb-3 sticky top-0 bg-[#0a0a0a] pb-2 border-b border-white/10 z-10">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                    <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                    <span className="ml-2 text-gray-500 flex items-center gap-1"><Terminal className="w-3 h-3"/> root@kali:~</span>
                  </div>
                  <span className="text-gray-500 text-xs">{subdomains.length} found | {(bytesReceived / 1024).toFixed(2)} KB scanned</span>
                </div>
                <div className="flex-1 flex flex-col gap-1">
                  {terminalLines.map((line, i) => (
                    <div key={i} className={`${line.startsWith('[!]') ? 'text-red-400' : line.startsWith('[+]') ? 'text-emerald-400' : 'text-gray-400'}`}>
                      {line}
                    </div>
                  ))}
                  <div className="animate-pulse text-emerald-500">_</div>
                  <div ref={terminalEndRef} />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Mode & Language Selector */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mx-auto w-full max-w-2xl">
          <div className="flex items-center justify-center gap-2 bg-[#141414] border border-white/10 p-1 rounded-full">
            <button
              type="button"
              onClick={() => setMode('standard')}
              className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-colors ${
                mode === 'standard' ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <List className="w-4 h-4" />
              Standard Subfinder
            </button>
            <button
              type="button"
              onClick={() => setMode('ai')}
              className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-colors ${
                mode === 'ai' ? 'bg-emerald-500/20 text-emerald-400' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Sparkles className="w-4 h-4" />
              AI Enhanced
            </button>
          </div>

          {mode === 'ai' && (
            <div className="flex items-center gap-2 bg-[#141414] border border-white/10 px-4 py-2 rounded-full">
              <Languages className="w-4 h-4 text-gray-500" />
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="bg-transparent border-none outline-none text-sm text-gray-300 cursor-pointer"
                disabled={isScanning || isAnalyzing}
              >
                <option value="English">English</option>
                <option value="Indonesian">Bahasa Indonesia</option>
                <option value="Spanish">Español</option>
                <option value="French">Français</option>
                <option value="German">Deutsch</option>
                <option value="Japanese">日本語</option>
              </select>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="max-w-2xl mx-auto w-full bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-xl flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Results Section */}
      <AnimatePresence>
        {(subdomains.length > 0 || analysis || whois) && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`grid grid-cols-1 ${mode === 'ai' ? 'lg:grid-cols-3' : ''} gap-8 mt-8`}
          >
            {/* Left Column: Subdomains List & WHOIS */}
            <div className={`${mode === 'ai' ? 'lg:col-span-1' : ''} flex flex-col gap-4`}>
              
              {/* WHOIS Info Card */}
              {whois && (
                <div className="bg-[#141414] border border-white/10 rounded-2xl overflow-hidden flex flex-col">
                  <div className="p-4 border-b border-white/10 bg-white/5 flex items-center gap-2">
                    <Info className="w-4 h-4 text-emerald-400" />
                    <h2 className="font-semibold">Domain Information</h2>
                  </div>
                  <div className="p-4 flex flex-col gap-3 text-sm">
                    {whois.registrar && (
                      <div className="flex justify-between items-center border-b border-white/5 pb-2">
                        <span className="text-gray-500">Registrar</span>
                        <span className="text-white font-medium text-right">{whois.registrar}</span>
                      </div>
                    )}
                    {whois.creation_date && (
                      <div className="flex justify-between items-center border-b border-white/5 pb-2">
                        <span className="text-gray-500 flex items-center gap-1"><Calendar className="w-3 h-3"/> Registered</span>
                        <span className="text-white font-mono">{new Date(whois.creation_date).toLocaleDateString()}</span>
                      </div>
                    )}
                    {whois.expiration_date && (
                      <div className="flex justify-between items-center">
                        <span className="text-gray-500 flex items-center gap-1"><Calendar className="w-3 h-3"/> Expires</span>
                        <span className="text-white font-mono">{new Date(whois.expiration_date).toLocaleDateString()}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Subdomains List */}
              <div className="bg-[#141414] border border-white/10 rounded-2xl overflow-hidden flex flex-col h-[600px]">
                <div className="p-4 border-b border-white/10 bg-white/5 flex items-center justify-between">
                  <h2 className="font-semibold flex items-center gap-2">
                    <Server className="w-4 h-4 text-emerald-400" />
                    Discovered Subdomains
                  </h2>
                  <span className="text-xs font-mono bg-white/10 px-2 py-1 rounded-md text-gray-300">
                    {subdomains.length} found
                  </span>
                </div>
                
                {/* Filters */}
                <div className="p-3 border-b border-white/10 bg-black/20 flex flex-col gap-2">
                  <div className="relative">
                    <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                      type="text"
                      placeholder="Filter by name or IP..."
                      value={filterText}
                      onChange={e => setFilterText(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-lg pl-9 pr-3 py-1.5 text-sm text-white placeholder:text-gray-600 outline-none focus:border-emerald-500/50 transition-colors"
                    />
                  </div>
                  <select
                    value={filterStatus}
                    onChange={e => setFilterStatus(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-gray-300 outline-none focus:border-emerald-500/50 transition-colors"
                  >
                    <option value="all">All Statuses</option>
                    <option value="resolvable">Resolvable (Has IP)</option>
                    <option value="unresolvable">Unresolvable (No IP)</option>
                    <option value="active">Active (HTTP 200-399)</option>
                    <option value="error">Error (HTTP 400+)</option>
                  </select>
                </div>

                <div className={`overflow-y-auto flex-1 p-2 custom-scrollbar ${mode === 'standard' ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 p-4' : ''}`}>
                  {filteredSubdomains.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-gray-500 text-sm">
                      No matching subdomains found.
                    </div>
                  ) : (
                    filteredSubdomains.map((sub, idx) => (
                      <a
                        key={idx}
                        href={`http://${sub.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-2 text-sm font-mono text-gray-300 hover:bg-white/5 hover:text-white rounded-lg transition-colors flex flex-col gap-1 group cursor-pointer border border-transparent hover:border-white/5"
                      >
                        <div className="flex items-center gap-2">
                          <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-emerald-400 transition-colors shrink-0" />
                          <span className="truncate font-medium">{sub.host}</span>
                        </div>
                        {sub.ip && (
                          <div className="pl-5 flex items-center gap-2">
                            <span className="text-xs text-emerald-500/70">{sub.ip}</span>
                            {sub.statusCode && (
                              <span className={`text-[10px] px-1.5 py-0.5 rounded-md ${
                                sub.statusCode >= 200 && sub.statusCode < 400 ? 'bg-emerald-500/20 text-emerald-400' :
                                sub.statusCode >= 400 ? 'bg-red-500/20 text-red-400' : 'bg-gray-500/20 text-gray-400'
                              }`}>
                                HTTP {sub.statusCode}
                              </span>
                            )}
                          </div>
                        )}
                      </a>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Right Column: AI Analysis */}
            {mode === 'ai' && (
              <div className="lg:col-span-2 flex flex-col gap-4">
                <div className="bg-[#141414] border border-white/10 rounded-2xl overflow-hidden flex flex-col min-h-[600px]">
                  <div className="p-4 border-b border-white/10 bg-white/5 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-emerald-400" />
                    <h2 className="font-semibold">AI Infrastructure Analysis</h2>
                    {isAnalyzing && (
                      <span className="ml-auto flex items-center gap-2 text-xs text-emerald-400 font-mono">
                        <Loader2 className="w-3 h-3 animate-spin" />
                        Generating insights...
                      </span>
                    )}
                  </div>
                  <div className="p-6 overflow-y-auto flex-1 prose prose-invert prose-emerald max-w-none custom-scrollbar">
                    {analysis ? (
                      <div className="markdown-body">
                        <Markdown>{analysis}</Markdown>
                      </div>
                    ) : (
                      <div className="h-full flex items-center justify-center text-gray-500 flex-col gap-4">
                        <Loader2 className="w-8 h-8 animate-spin text-emerald-500/50" />
                        <p>Analyzing {subdomains.length} subdomains with Gemini...</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
      {/* History Modal */}
      <AnimatePresence>
        {showHistory && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-[#141414] border border-white/10 rounded-2xl w-full max-w-2xl max-h-[80vh] flex flex-col overflow-hidden shadow-2xl"
            >
              <div className="p-4 border-b border-white/10 flex items-center justify-between bg-white/5">
                <h2 className="font-semibold flex items-center gap-2">
                  <History className="w-5 h-5 text-emerald-400" />
                  Scan History
                </h2>
                <button
                  onClick={() => setShowHistory(false)}
                  className="p-2 hover:bg-white/10 rounded-full transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="overflow-y-auto p-4 flex flex-col gap-2 custom-scrollbar">
                {history.length === 0 ? (
                  <div className="text-center text-gray-500 py-8">No scan history found.</div>
                ) : (
                  history.map(item => (
                    <div key={item.id} className="rounded-xl border border-white/5 bg-white/5 overflow-hidden flex flex-col">
                      <div
                        onClick={() => loadHistoryItem(item)}
                        className="p-4 hover:bg-white/10 transition-colors cursor-pointer flex items-center justify-between group"
                      >
                        <div className="flex flex-col gap-1">
                          <div className="font-mono text-white font-medium flex items-center gap-2">
                            {item.domain}
                            <span className={`text-[10px] px-2 py-0.5 rounded-full uppercase tracking-wider ${item.mode === 'ai' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-white/10 text-gray-300'}`}>
                              {item.mode}
                            </span>
                          </div>
                          <div className="text-xs text-gray-500 flex items-center gap-3">
                            <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {new Date(item.date).toLocaleString()}</span>
                            <span className="flex items-center gap-1"><Server className="w-3 h-3" /> {item.count} subdomains</span>
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-600 group-hover:text-emerald-400 transition-colors" />
                      </div>
                      <div className="px-4 pb-4 pt-0 bg-transparent" onClick={e => e.stopPropagation()}>
                        <textarea
                          value={item.notes || ''}
                          onChange={(e) => updateHistoryNote(item.id, e.target.value)}
                          placeholder="Add notes for this scan..."
                          className="w-full bg-black/50 border border-white/10 rounded-lg p-2 text-sm text-gray-300 outline-none focus:border-emerald-500/50 transition-colors resize-none custom-scrollbar"
                          rows={2}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
