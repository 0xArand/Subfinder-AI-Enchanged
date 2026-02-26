'use client';

import React, { useState } from 'react';
import { Search, Loader2, ShieldAlert, Server, Activity, Globe, ChevronRight } from 'lucide-react';
import { GoogleGenAI } from '@google/genai';
import Markdown from 'react-markdown';
import { motion, AnimatePresence } from 'motion/react';

export default function Page() {
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [subdomains, setSubdomains] = useState<string[]>([]);
  const [analysis, setAnalysis] = useState<string>('');
  const [error, setError] = useState<string>('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;

    // Basic domain validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Please enter a valid domain (e.g., example.com)');
      return;
    }

    setError('');
    setSubdomains([]);
    setAnalysis('');
    setIsScanning(true);

    try {
      // 1. Fetch subdomains
      const res = await fetch(`/api/subdomains?domain=${encodeURIComponent(domain)}`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch subdomains');
      }

      const foundSubdomains = data.subdomains || [];
      setSubdomains(foundSubdomains);
      setIsScanning(false);

      if (foundSubdomains.length === 0) {
        setError('No subdomains found for this domain.');
        return;
      }

      // 2. Analyze with AI
      setIsAnalyzing(true);
      
      const ai = new GoogleGenAI({ apiKey: process.env.NEXT_PUBLIC_GEMINI_API_KEY });
      
      const prompt = `
You are an expert cybersecurity analyst and infrastructure architect.
I have performed a subdomain enumeration on the domain "${domain}".
Here are the discovered subdomains (${foundSubdomains.length} total):

${foundSubdomains.slice(0, 500).join('\n')}
${foundSubdomains.length > 500 ? '\n... (truncated for length)' : ''}

Please provide a comprehensive analysis of these subdomains:
1. **Categorization**: Group them by likely purpose (e.g., Production, Staging/Dev, Internal/Admin, Marketing, Mail, etc.).
2. **Security Posture**: Identify any potentially sensitive or vulnerable exposures (e.g., exposed dev environments, admin panels, old versions).
3. **Infrastructure Insights**: What can we infer about their tech stack or infrastructure setup based on these names?
4. **Recommendations**: Brief actionable advice for the security team.

Format the response in clean Markdown. Use headings, bullet points, and bold text for readability. Keep it professional and concise.
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

    } catch (err: any) {
      console.error(err);
      setError(err.message || 'An error occurred during the scan.');
    } finally {
      setIsScanning(false);
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-12 flex flex-col gap-8">
      {/* Header */}
      <header className="flex flex-col gap-4 items-center text-center">
        <div className="inline-flex items-center justify-center p-3 bg-emerald-500/10 rounded-2xl mb-2">
          <Activity className="w-8 h-8 text-emerald-400" />
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight">
          Subfinder <span className="text-emerald-400">AI</span>
        </h1>
        <p className="text-gray-400 max-w-2xl text-lg">
          Discover subdomains and instantly analyze infrastructure patterns, security posture, and exposed environments using Gemini AI.
        </p>
      </header>

      {/* Search Form */}
      <form onSubmit={handleScan} className="w-full max-w-2xl mx-auto relative group">
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
          <button
            type="submit"
            disabled={isScanning || isAnalyzing || !domain}
            className="bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-6 py-3 rounded-full transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Scanning
              </>
            ) : isAnalyzing ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Analyzing
              </>
            ) : (
              <>
                <Search className="w-5 h-5" />
                Analyze
              </>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="max-w-2xl mx-auto w-full bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-xl flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Results Section */}
      <AnimatePresence>
        {(subdomains.length > 0 || analysis) && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8"
          >
            {/* Left Column: Subdomains List */}
            <div className="lg:col-span-1 flex flex-col gap-4">
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
                <div className="overflow-y-auto flex-1 p-2 custom-scrollbar">
                  {subdomains.map((sub, idx) => (
                    <div
                      key={idx}
                      className="px-3 py-2 text-sm font-mono text-gray-300 hover:bg-white/5 hover:text-white rounded-lg transition-colors flex items-center gap-2 group cursor-default"
                    >
                      <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-emerald-400 transition-colors" />
                      <span className="truncate">{sub}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Column: AI Analysis */}
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
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
