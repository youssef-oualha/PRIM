import React, { useState, useCallback } from 'react';
import rulesConfig from './recyf_rules.json';

const API_ENDPOINT = 'http://localhost:8000/api/submit-audit-result';

/**
 * Dynamic, decoupled predicate evaluator for the ReCyF JSON Rules Engine.
 * Supports EQUALS, NOT_EQUALS, IN, and CONTAINS without hardcoding business rules.
 */
const evaluateCondition = (item, condition) => {
  const actualValue = item?.[condition.field];
  switch (condition.operator) {
    case 'EQUALS':
      return actualValue === condition.value;
    case 'NOT_EQUALS':
      return actualValue !== condition.value;
    case 'IN':
      return Array.isArray(condition.value) && condition.value.includes(actualValue);
    case 'CONTAINS':
      return Array.isArray(actualValue) && actualValue.includes(condition.value);
    default:
      throw new Error(`Unsupported rule operator: ${condition.operator}`);
  }
};

/**
 * Generates a client-side SHA-256 hash of the raw file for zero-knowledge audit proof.
 */
const computeFileSHA256 = async (textContent) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(textContent);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

export default function AuditDashboard() {
  const activeRule = rulesConfig.objectives.find((obj) => obj.objective_id === 10);

  const [isDragging, setIsDragging] = useState(false);
  const [fileName, setFileName] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stageText, setStageText] = useState('Awaiting client configuration export...');
  const [error, setError] = useState(null);

  // Sensitive findings stay strictly in volatile browser state (RAM)
  const [localFindings, setLocalFindings] = useState(null);
  // Sanitized payload sent over the wire
  const [zkPayload, setZkPayload] = useState(null);
  // Backend scoring response
  const [serverResponse, setServerResponse] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const processAuditFile = useCallback(
    async (file) => {
      setError(null);
      setLocalFindings(null);
      setZkPayload(null);
      setServerResponse(null);
      setFileName(file.name);

      try {
        // Stage 1: Read file locally in browser memory
        setProgress(25);
        setStageText('Reading file in browser memory sandbox...');
        const rawText = await file.text();
        const parsedData = JSON.parse(rawText);

        // Stage 2: Compute Zero-Knowledge cryptographic proof
        setProgress(50);
        setStageText('Computing SHA-256 Zero-Knowledge evidence fingerprint...');
        const evidenceHash = await computeFileSHA256(rawText);

        // Stage 3: Execute Modular Rules Engine
        setProgress(75);
        setStageText(`Evaluating against ${activeRule.code}...`);
        const { target_collection, scope_filter, assertion } = activeRule.evaluation_logic;
        const collection = parsedData[target_collection];

        if (!Array.isArray(collection)) {
          throw new Error(
            `Invalid schema: Expected array "${target_collection}" in uploaded JSON export.`
          );
        }

        // Filter assets in scope (e.g., role === "admin")
        const scopedAssets = collection.filter((item) => evaluateCondition(item, scope_filter));

        if (scopedAssets.length === 0) {
          throw new Error(
            `No assets matched scope filter (${scope_filter.field} ${scope_filter.operator} "${scope_filter.value}").`
          );
        }

        // Identify non-compliant assets (e.g., mfa_enabled !== true)
        const failedAssets = scopedAssets.filter((item) => !evaluateCondition(item, assertion));
        const isCompliant = failedAssets.length === 0;
        const complianceStatus = isCompliant ? 'Compliant' : 'Non-Compliant';

        // Store sensitive details ONLY in local browser memory for the user's eyes
        setLocalFindings({
          totalRecords: collection.length,
          scopedCount: scopedAssets.length,
          failedCount: failedAssets.length,
          failedAccounts: failedAssets.map((u) => ({
            id: u.id || 'N/A',
            username: u.username || 'Unknown',
            role: u.role
          }))
        });

        // Build strictly sanitized Zero-Knowledge metadata payload
        const sanitizedPayload = {
          objective: activeRule.objective_id,
          rule_code: activeRule.code,
          status: complianceStatus,
          scoped_assets_count: scopedAssets.length,
          failed_assets_count: failedAssets.length,
          evidence_sha256: evidenceHash
        };
        setZkPayload(sanitizedPayload);

        // Stage 4: Transmit ONLY sanitized metadata to FastAPI Backend
        setProgress(90);
        setStageText('Transmitting anonymized compliance metadata to AIDATACY Scoring Engine...');
        setIsSubmitting(true);

        const response = await fetch(API_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(sanitizedPayload)
        });

        if (!response.ok) {
          const errBody = await response.json().catch(() => ({}));
          throw new Error(errBody.detail || `Backend returned HTTP ${response.status}`);
        }

        const resultData = await response.json();
        setServerResponse(resultData);
        setProgress(100);
        setStageText('Zero-Knowledge Audit complete. Raw evidence retained locally.');
      } catch (err) {
        setProgress(0);
        setStageText('Audit aborted due to error.');
        setError(err.message || 'Failed to parse or evaluate JSON configuration file.');
      } finally {
        setIsSubmitting(false);
      }
    },
    [activeRule]
  );

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files?.[0];
    if (droppedFile) processAuditFile(droppedFile);
  };

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) processAuditFile(selectedFile);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-10 font-sans">
      <div className="max-w-5xl mx-auto space-y-8">
        {/* Header */}
        <header className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-6 gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 text-xs font-semibold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
                Zero-Knowledge Client Sandbox
              </span>
              <span className="text-xs text-slate-400 font-mono">{rulesConfig.framework}</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white mt-2">
              AIDATACY — Sovereign NIS2 & ReCyF Audit Platform
            </h1>
          </div>
          <div className="text-left md:text-right bg-slate-900/90 border border-slate-800 px-4 py-3 rounded-lg">
            <p className="text-xs text-slate-400 uppercase tracking-wider">Active Rule Module</p>
            <p className="text-sm font-semibold text-indigo-400">{activeRule.code}</p>
            <p className="text-xs text-slate-500">Weight: {activeRule.weight} pts ({activeRule.criticality})</p>
          </div>
        </header>

        {/* Active Objective Banner */}
        <section className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
          <div className="flex flex-col md:flex-row justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">{activeRule.title}</h2>
              <p className="text-sm text-slate-300 mt-1">{activeRule.requirement}</p>
              <p className="text-xs text-slate-400 mt-2 font-mono">
                Legal Basis: {activeRule.nis2_mapping}
              </p>
            </div>
            <div className="flex items-center">
              <div className="text-xs bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-slate-300">
                <div>Scope: {activeRule.evaluation_logic.scope_filter.field} == "{String(activeRule.evaluation_logic.scope_filter.value)}"</div>
                <div>Assert: {activeRule.evaluation_logic.assertion.field} == {String(activeRule.evaluation_logic.assertion.value)}</div>
              </div>
            </div>
          </div>
        </section>

        {/* Drag-and-Drop Zone */}
        <section
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 ${
            isDragging
              ? 'border-indigo-400 bg-indigo-950/20'
              : 'border-slate-700 bg-slate-900/40 hover:border-slate-600'
          }`}
        >
          <input
            type="file"
            accept=".json,application/json"
            onChange={handleFileSelect}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-full bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center mx-auto text-indigo-400 font-bold text-xl">
              ⚡
            </div>
            <h3 className="text-base font-medium text-white">
              Drop <span className="font-mono text-indigo-400">dummy_entra_id_export.json</span> here, or click to browse
            </h3>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              100% Client-Side Parsing: Your raw IAM configuration never leaves this browser tab. PII, usernames, and tenant IDs are stripped before scoring.
            </p>
            {fileName && (
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-slate-800 text-xs font-mono text-emerald-300 mt-2">
                <span>Loaded File: {fileName}</span>
              </div>
            )}
          </div>
        </section>

        {/* Progress Bar */}
        {(progress > 0 || error) && (
          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex justify-between items-center text-xs">
              <span className="font-medium text-slate-300">{stageText}</span>
              <span className="font-mono text-indigo-400">{progress}%</span>
            </div>
            <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  error ? 'bg-rose-500' : progress === 100 ? 'bg-emerald-500' : 'bg-indigo-500'
                }`}
                style={{ width: `${error ? 100 : progress}%` }}
              />
            </div>
            {error && (
              <div className="p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg text-xs text-rose-300 font-mono">
                [Audit Engine Error]: {error}
              </div>
            )}
          </section>
        )}

        {/* Results Grid: Browser-Only Findings vs. Backend Zero-Knowledge Telemetry */}
        {localFindings && zkPayload && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left Column: Local In-Memory Inspection (Never Transmitted) */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  1. Local Browser RAM Evidence
                </h3>
                <span className="px-2 py-0.5 text-[11px] font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded">
                  NEVER SENT TO SERVER
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-xs text-slate-400">Total Identities</div>
                  <div className="text-xl font-bold text-white mt-1">{localFindings.totalRecords}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-xs text-slate-400">Admins in Scope</div>
                  <div className="text-xl font-bold text-indigo-400 mt-1">{localFindings.scopedCount}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-xs text-slate-400">MFA Violations</div>
                  <div
                    className={`text-xl font-bold mt-1 ${
                      localFindings.failedCount > 0 ? 'text-rose-400' : 'text-emerald-400'
                    }`}
                  >
                    {localFindings.failedCount}
                  </div>
                </div>
              </div>

              {localFindings.failedAccounts.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-xs text-rose-300 font-medium">
                    Non-Compliant Admin Accounts (Visible Locally Only):
                  </p>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg divide-y divide-slate-800 max-h-44 overflow-y-auto">
                    {localFindings.failedAccounts.map((acc) => (
                      <div key={acc.id} className="p-2.5 flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-200 truncate">{acc.username}</span>
                        <span className="px-2 py-0.5 bg-rose-500/20 text-rose-300 rounded">
                          MFA: FALSE
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-emerald-950/30 border border-emerald-500/30 rounded-lg text-xs text-emerald-300">
                  All privileged accounts satisfy ReCyF Objective 10 MFA enforcement.
                </div>
              )}
            </div>

            {/* Right Column: Zero-Knowledge Network Payload & Server Score */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  2. Outbound Zero-Knowledge Payload
                </h3>
                <span className="px-2 py-0.5 text-[11px] font-mono bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 rounded">
                  POST /api/submit-audit-result
                </span>
              </div>

              <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto">
                {JSON.stringify(zkPayload, null, 2)}
              </pre>

              {isSubmitting && (
                <div className="text-xs text-slate-400 animate-pulse">
                  Calculating NIS2 readiness score on backend...
                </div>
              )}

              {serverResponse && (
                <div className="border-t border-slate-800 pt-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-xs text-slate-400 uppercase tracking-wider block">
                        Audit Status
                      </span>
                      <span
                        className={`inline-block mt-1 px-3 py-1 rounded-full text-xs font-bold uppercase ${
                          serverResponse.status === 'Compliant'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        }`}
                      >
                        {serverResponse.status}
                      </span>
                    </div>

                    <div className="text-right">
                      <span className="text-xs text-slate-400 uppercase tracking-wider block">
                        NIS2 Readiness Score
                      </span>
                      <span className="text-3xl font-extrabold text-white">
                        {serverResponse.nis2_readiness_score}
                        <span className="text-sm font-normal text-slate-400">/100</span>
                      </span>
                    </div>
                  </div>

                  <div className="bg-indigo-950/30 border border-indigo-500/30 rounded-lg p-3.5 space-y-1">
                    <div className="text-xs font-semibold text-indigo-300 uppercase tracking-wider">
                      Remediation Advisory
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed">
                      {serverResponse.remediation_recommendation}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}