import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

import { FindingsTreeDataProvider } from './findingsTree';
import { installPythonRuntime, runContractGuardScan } from './pythonBridge';
import { Finding, ScanPayload, Severity } from './types';

const sourceName = 'ContractGuard';
const analyzerIds = ['json', 'sql', 'regex', 'secrets', 'pii', 'config', 'dockerfile', 'deps'] as const;
const supportedExtensions = new Set([
  '.json',
  '.sql',
  '.txt',
  '.regex',
  '.env',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.properties',
  '.dockerfile'
]);

function riskSummaryForGrade(grade: string): string {
  switch (grade) {
    case 'A':
      return 'Minimal risk. Good security posture.';
    case 'B':
      return 'Low risk. A few issues to address before production.';
    case 'C':
      return 'Moderate risk. Several issues need attention.';
    case 'D':
      return 'High risk. Significant security issues detected.';
    default:
      return 'CRITICAL RISK. Deployment must be blocked until issues are resolved.';
  }
}

class ContractGuardController implements vscode.Disposable {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection('contractguard');
  private readonly tree = new FindingsTreeDataProvider();
  private readonly statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  private scanTimer: NodeJS.Timeout | undefined;
  private running = false;
  private queuedRequest:
    | { targetPath: string; analyzer: string; includeSarif: boolean }
    | undefined;
  private queuedScanPromise: Promise<ScanPayload> | undefined;
  private resolveQueuedScan: ((payload: ScanPayload) => void) | undefined;
  private rejectQueuedScan: ((error: unknown) => void) | undefined;
  private scheduledScanAction: (() => Promise<void>) | undefined;
  private latestPayload: ScanPayload | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.statusBar.name = 'ContractGuard';
    this.statusBar.command = 'contractguard.scanWorkspace';
    this.statusBar.text = 'ContractGuard: idle';
    this.statusBar.show();

    context.subscriptions.push(
      this.diagnostics,
      this.statusBar,
      vscode.window.registerTreeDataProvider('contractguard.findings', this.tree)
    );
  }

  dispose(): void {
    if (this.scanTimer) {
      clearTimeout(this.scanTimer);
    }
    this.diagnostics.dispose();
    this.statusBar.dispose();
  }

  async scanWorkspace(includeSarif = false): Promise<void> {
    const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspacePath) {
      vscode.window.showInformationMessage('ContractGuard requires an open workspace.');
      return;
    }
    await this.runWorkspaceScan(workspacePath, includeSarif);
  }

  async scanCurrentFile(): Promise<void> {
    const document = vscode.window.activeTextEditor?.document;
    if (!document) {
      vscode.window.showInformationMessage('No active file to scan.');
      return;
    }
    const filePath = document.uri.fsPath;
    const analyzer = this.selectAnalyzer(filePath);
    if (analyzer === 'all') {
      vscode.window.showInformationMessage(`ContractGuard does not support scanning this file type: ${path.basename(filePath)}`);
      return;
    }
    await this.runScan(filePath, analyzer, false);
  }

  clear(): void {
    this.latestPayload = undefined;
    this.tree.clear();
    this.diagnostics.clear();
    this.statusBar.text = 'ContractGuard: cleared';
  }

  async exportSarif(): Promise<void> {
    const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspacePath) {
      vscode.window.showInformationMessage('ContractGuard requires an open workspace.');
      return;
    }

    const payload = this.latestPayload?.sarif ? this.latestPayload : await this.collectWorkspaceSarif(workspacePath);
    if (!payload.sarif) {
      vscode.window.showWarningMessage('ContractGuard did not return SARIF data.');
      return;
    }

    const target = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(path.join(workspacePath, 'contractguard.sarif')),
      filters: { SARIF: ['sarif', 'json'] }
    });
    if (!target) {
      return;
    }

    await vscode.workspace.fs.writeFile(target, new TextEncoder().encode(JSON.stringify(payload.sarif, null, 2)));
    vscode.window.showInformationMessage(`ContractGuard SARIF exported to ${target.fsPath}`);
  }

  scheduleWorkspaceScan(): void {
    this.scheduleScan(async () => {
      await this.scanWorkspace(false);
    });
  }

  scheduleFileScan(filePath: string): void {
    const analyzer = this.selectAnalyzer(filePath);
    if (analyzer === 'all') {
      return;
    }

    this.scheduleScan(async () => {
      await this.runScan(filePath, analyzer, false);
    });
  }

  async openFinding(finding: Finding): Promise<void> {
    const parsed = this.parseLocation(finding.location);
    if (!parsed) {
      return;
    }

    const document = await vscode.workspace.openTextDocument(parsed.uri);
    const editor = await vscode.window.showTextDocument(document, { preview: false });
    const position = new vscode.Position(Math.max(parsed.line - 1, 0), 0);
    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
  }

  private async collectWorkspaceSarif(workspacePath: string): Promise<ScanPayload> {
    return await this.runWorkspaceScan(workspacePath, true);
  }

  private async runWorkspaceScan(workspacePath: string, includeSarif: boolean): Promise<ScanPayload> {
    const analyzers = this.getEnabledAnalyzers();
    const payloads: ScanPayload[] = [];

    for (const analyzer of analyzers) {
      payloads.push(await this.runScan(workspacePath, analyzer, includeSarif));
    }

    return this.mergePayloads(workspacePath, payloads, includeSarif);
  }

  private async runScan(targetPath: string, analyzer: string, includeSarif: boolean): Promise<ScanPayload> {
    if (this.running) {
      this.queuedRequest = { targetPath, analyzer, includeSarif };
      if (!this.queuedScanPromise) {
        this.queuedScanPromise = new Promise<ScanPayload>((resolve, reject) => {
          this.resolveQueuedScan = resolve;
          this.rejectQueuedScan = reject;
        });
      }
      return await this.queuedScanPromise;
    }

    this.running = true;
    this.statusBar.text = 'ContractGuard: scanning...';

    try {
      const payload = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Window,
          title: `ContractGuard scanning ${path.basename(targetPath) || targetPath}`
        },
        async () => await runContractGuardScan(this.context, targetPath, analyzer, includeSarif)
      );

      const filteredFindings = this.filterFindings(payload.findings);
      const normalizedPayload: ScanPayload = {
        ...payload,
        findings: filteredFindings,
        score: this.recomputeScore(payload.score, filteredFindings)
      };
      this.latestPayload = normalizedPayload;
      this.publishDiagnostics(filteredFindings);
      this.tree.setFindings(filteredFindings);
      this.updateStatusBar(normalizedPayload);
      return normalizedPayload;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.statusBar.text = 'ContractGuard: runtime error';
      const action = await vscode.window.showErrorMessage(`ContractGuard scan failed: ${message}`, 'Install Runtime');
      if (action === 'Install Runtime') {
        await installPythonRuntime(this.context);
      }
      throw error;
    } finally {
      this.running = false;
      const queuedRequest = this.queuedRequest;
      const resolveQueuedScan = this.resolveQueuedScan;
      const rejectQueuedScan = this.rejectQueuedScan;
      this.queuedRequest = undefined;
      this.queuedScanPromise = undefined;
      this.resolveQueuedScan = undefined;
      this.rejectQueuedScan = undefined;
      if (queuedRequest && resolveQueuedScan && rejectQueuedScan) {
        void this.runScan(queuedRequest.targetPath, queuedRequest.analyzer, queuedRequest.includeSarif).then(
          resolveQueuedScan,
          rejectQueuedScan
        );
      }
    }
  }

  private scheduleScan(action: () => Promise<void>): void {
    const debounceMs = vscode.workspace.getConfiguration('contractguard').get<number>('scanDebounceMs', 600);
    this.scheduledScanAction = action;
    if (this.scanTimer) {
      clearTimeout(this.scanTimer);
    }
    this.scanTimer = setTimeout(() => {
      const scheduledScanAction = this.scheduledScanAction;
      this.scheduledScanAction = undefined;
      if (scheduledScanAction) {
        void scheduledScanAction();
      }
    }, debounceMs);
  }

  private getEnabledAnalyzers(): string[] {
    const configured = vscode.workspace.getConfiguration('contractguard').get<string[]>('enabledAnalyzers', []);
    if (configured.length === 0) {
      return [...analyzerIds];
    }
    const configuredSet = new Set(configured);
    return analyzerIds.filter((analyzer) => configuredSet.has(analyzer));
  }

  private mergePayloads(workspacePath: string, payloads: ScanPayload[], includeSarif: boolean): ScanPayload {
    const findings = payloads.flatMap((payload) => payload.findings);
    const score = this.recomputeScore(
      payloads[0]?.score ?? {
        grade: 'A',
        score: 100,
        total_findings: 0,
        block_count: 0,
        critical_count: 0,
        warning_count: 0,
        info_count: 0,
        risk_summary: '',
        attack_surface: [],
        top_risks: []
      },
      findings
    );
    const sarif = includeSarif
      ? {
          version: '2.1.0',
          $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
          runs: payloads.flatMap((payload) => {
            const runs = payload.sarif && 'runs' in payload.sarif ? payload.sarif.runs : [];
            return Array.isArray(runs) ? runs : [];
          })
        }
      : null;

    const mergedPayload: ScanPayload = {
      target: workspacePath,
      analyzer: payloads.length === 1 ? payloads[0].analyzer : 'all',
      engine_version: payloads[0]?.engine_version ?? 'unknown',
      generated_at: payloads[0]?.generated_at ?? null,
      findings,
      score,
      sarif
    };
    this.latestPayload = mergedPayload;
    this.publishDiagnostics(findings);
    this.tree.setFindings(findings);
    this.updateStatusBar(mergedPayload);
    return mergedPayload;
  }

  private filterFindings(findings: Finding[]): Finding[] {
    const disabledRules = new Set(
      vscode.workspace.getConfiguration('contractguard').get<string[]>('disabledRules', []).map((item) => item.trim())
    );
    const enabledAnalyzers = new Set(
      vscode.workspace.getConfiguration('contractguard').get<string[]>('enabledAnalyzers', [])
    );

    return findings.filter((finding) => {
      if (disabledRules.has(finding.rule_id)) {
        return false;
      }
      if (enabledAnalyzers.size === 0) {
        return true;
      }
      const prefix = this.inferAnalyzerFromRule(finding.rule_id);
      return enabledAnalyzers.has(prefix);
    });
  }

  private recomputeScore(score: ScanPayload['score'], findings: Finding[]): ScanPayload['score'] {
    const counts = {
      block_count: findings.filter((item) => item.severity === 'block').length,
      critical_count: findings.filter((item) => item.severity === 'critical').length,
      warning_count: findings.filter((item) => item.severity === 'warning').length,
      info_count: findings.filter((item) => item.severity === 'info').length
    };
    const attackSurface = [
      ...new Set(
        findings
          .map((item) => item.attack_vector)
          .filter((attackVector) => typeof attackVector === 'string' && attackVector.trim().length > 0)
      )
    ];
    const topRisks = [...new Set(findings.map((item) => `[${item.severity.toUpperCase()}] ${item.description}`))].slice(0, 5);
    const scoreValue = Math.max(
      0,
      100 - counts.block_count * 20 - counts.critical_count * 10 - counts.warning_count * 4 - counts.info_count
    );
    const grade =
      counts.block_count > 0 ? 'F'
      : scoreValue >= 90 ? 'A'
      : scoreValue >= 75 ? 'B'
      : scoreValue >= 55 ? 'C'
      : scoreValue >= 35 ? 'D'
      : 'F';

    return {
      ...score,
      grade,
      score: counts.block_count > 0 ? Math.min(scoreValue, 15) : scoreValue,
      ...counts,
      total_findings: findings.length,
      risk_summary: riskSummaryForGrade(grade),
      attack_surface: attackSurface,
      top_risks: topRisks
    };
  }

  private updateStatusBar(payload: ScanPayload): void {
    this.statusBar.text = `ContractGuard ${payload.score.grade} ${payload.score.score}/100`;
    this.statusBar.tooltip = `${payload.score.total_findings} findings`;
    switch (payload.score.grade) {
      case 'A':
      case 'B':
        this.statusBar.backgroundColor = undefined;
        break;
      case 'C':
        this.statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        break;
      default:
        this.statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        break;
    }
  }

  private publishDiagnostics(findings: Finding[]): void {
    this.diagnostics.clear();
    const buckets = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      const parsed = this.parseLocation(finding.location);
      if (!parsed) {
        continue;
      }

      const range = new vscode.Range(
        new vscode.Position(Math.max(parsed.line - 1, 0), 0),
        new vscode.Position(Math.max(parsed.line - 1, 0), 200)
      );
      const diagnostic = new vscode.Diagnostic(range, this.formatMessage(finding), this.toDiagnosticSeverity(finding.severity));
      diagnostic.code = finding.rule_id;
      diagnostic.source = sourceName;

      const items = buckets.get(parsed.uri.fsPath) ?? [];
      items.push(diagnostic);
      buckets.set(parsed.uri.fsPath, items);
    }

    for (const [filePath, diagnostics] of buckets.entries()) {
      this.diagnostics.set(vscode.Uri.file(filePath), diagnostics);
    }
  }

  private formatMessage(finding: Finding): string {
    const bits = [finding.description, finding.suggestion];
    if (finding.cwe) {
      bits.push(finding.cwe);
    }
    return bits.filter(Boolean).join(' ');
  }

  private toDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'block':
      case 'critical':
        return vscode.DiagnosticSeverity.Error;
      case 'warning':
        return vscode.DiagnosticSeverity.Warning;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  private inferAnalyzerFromRule(ruleId: string): string {
    if (ruleId.startsWith('JSON')) return 'json';
    if (ruleId.startsWith('SQL')) return 'sql';
    if (ruleId.startsWith('REG')) return 'regex';
    if (ruleId.startsWith('SEC')) return 'secrets';
    if (ruleId.startsWith('PII')) return 'pii';
    if (ruleId.startsWith('CFG')) return 'config';
    if (ruleId.startsWith('DOCK')) return 'dockerfile';
    if (ruleId.startsWith('DEP') || ruleId.startsWith('CVE')) return 'deps';
    return 'secrets';
  }

  private parseLocation(location: string): { uri: vscode.Uri; line: number } | undefined {
    if (!location) {
      return undefined;
    }

    const parts = location.match(/^(.*?)(?::(\d+))?$/);
    if (!parts) {
      return undefined;
    }
    const filePath = parts[1];
    if (!filePath || !fs.existsSync(filePath)) {
      return undefined;
    }
    return {
      uri: vscode.Uri.file(filePath),
      line: parts[2] ? Number(parts[2]) : 1
    };
  }

  private selectAnalyzer(filePath: string): string {
    const extension = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    if (extension === '.sql') return 'sql';
    if (extension === '.json') return 'json';
    if (extension === '.regex') return 'regex';
    if (basename === 'dockerfile' || extension === '.dockerfile') return 'dockerfile';
    if (basename.startsWith('requirements') || basename === 'constraints.txt') return 'deps';
    if (extension === '.env' || extension === '.yaml' || extension === '.yml' || extension === '.toml' || extension === '.ini' || extension === '.cfg' || extension === '.conf' || extension === '.properties') {
      return 'config';
    }
    if (supportedExtensions.has(extension)) {
      return 'secrets';
    }
    return 'all';
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const controller = new ContractGuardController(context);

  context.subscriptions.push(
    controller,
    vscode.commands.registerCommand('contractguard.scanWorkspace', async () => {
      await controller.scanWorkspace(false);
    }),
    vscode.commands.registerCommand('contractguard.scanCurrentFile', async () => {
      await controller.scanCurrentFile();
    }),
    vscode.commands.registerCommand('contractguard.exportSarif', async () => {
      await controller.exportSarif();
    }),
    vscode.commands.registerCommand('contractguard.clearFindings', () => {
      controller.clear();
    }),
    vscode.commands.registerCommand('contractguard.openFinding', async (finding: Finding) => {
      await controller.openFinding(finding);
    }),
    vscode.commands.registerCommand('contractguard.installRuntime', async () => {
      await installPythonRuntime(context);
      vscode.window.showInformationMessage('ContractGuard Python runtime dependencies installed.');
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (!vscode.workspace.getConfiguration('contractguard').get<boolean>('scanOnSave', true)) {
        return;
      }
      if (document.uri.scheme !== 'file') {
        return;
      }
      controller.scheduleFileScan(document.uri.fsPath);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('contractguard')) {
        controller.scheduleWorkspaceScan();
      }
    })
  );
}

export function deactivate(): void {}
