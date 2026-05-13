import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

import { ScanPayload } from './types';

function getConfig(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('contractguard');
}

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function getBundledRulesPath(context: vscode.ExtensionContext): string {
  const configured = getConfig().get<string>('rulesDirectory', '').trim();
  return configured ? configured : path.join(context.extensionPath, 'rules');
}

function getMinimumConfidence(): string {
  const configured = getConfig().get<string>('minimumConfidence', 'medium').trim();
  return ['low', 'medium', 'high'].includes(configured) ? configured : 'medium';
}

function getIncludeFixtures(): boolean {
  return getConfig().get<boolean>('includeFixtures', false);
}

function getPythonExecutable(): string {
  const configured = getConfig().get<string>('pythonPath', '').trim();
  if (configured) {
    return configured;
  }

  const workspaceRoot = getWorkspaceRoot();
  if (workspaceRoot) {
    const candidates = [
      path.join(workspaceRoot, '.venv', 'Scripts', 'python.exe'),
      path.join(workspaceRoot, '.venv', 'bin', 'python'),
      path.join(workspaceRoot, 'venv', 'Scripts', 'python.exe'),
      path.join(workspaceRoot, 'venv', 'bin', 'python')
    ];
    const match = candidates.find((candidate) => fs.existsSync(candidate));
    if (match) {
      return match;
    }
  }

  return process.platform === 'win32' ? 'python' : 'python3';
}

function getPythonPathEntries(context: vscode.ExtensionContext): string[] {
  const bundledSrc = path.join(context.extensionPath, 'src');
  const entries = [bundledSrc];
  const existing = process.env.PYTHONPATH?.trim();
  if (existing) {
    entries.push(existing);
  }
  return entries;
}

export async function runContractGuardScan(
  context: vscode.ExtensionContext,
  targetPath: string,
  analyzer: string,
  includeSarif: boolean
): Promise<ScanPayload> {
  const python = getPythonExecutable();
  const dbPath = getConfig().get<string>('sqlExplainDatabase', '').trim();
  const args = [
    '-m',
    'contractguard.bridge',
    'scan',
    '--path',
    targetPath,
    '--analyzer',
    analyzer,
    '--rules-dir',
    getBundledRulesPath(context),
    '--min-confidence',
    getMinimumConfidence()
  ];

  if (getIncludeFixtures()) {
    args.push('--include-fixtures');
  }

  if (dbPath) {
    args.push('--db', dbPath);
  }
  if (includeSarif) {
    args.push('--include-sarif');
  }

  const env = {
    ...process.env,
    PYTHONPATH: getPythonPathEntries(context).join(path.delimiter)
  };

  return await new Promise<ScanPayload>((resolve, reject) => {
    const child = cp.spawn(python, args, {
      cwd: getWorkspaceRoot() ?? context.extensionPath,
      env,
      windowsHide: true
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      reject(error);
    });

    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `ContractGuard bridge exited with code ${code}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout) as ScanPayload);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        reject(new Error(`Failed to parse ContractGuard output: ${detail}\n${stdout}`));
      }
    });
  });
}

export async function installPythonRuntime(context: vscode.ExtensionContext): Promise<void> {
  const python = getPythonExecutable();
  const requirementsFile = path.join(context.extensionPath, 'python-requirements.txt');
  const args = ['-m', 'pip', 'install', '-r', requirementsFile];

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Installing ContractGuard Python dependencies'
    },
    async () =>
      await new Promise<void>((resolve, reject) => {
        const child = cp.spawn(python, args, {
          cwd: getWorkspaceRoot() ?? context.extensionPath,
          windowsHide: true
        });

        let stderr = '';
        child.stderr.on('data', (chunk: Buffer | string) => {
          stderr += chunk.toString();
        });
        child.on('error', reject);
        child.on('close', (code) => {
          if (code === 0) {
            resolve();
            return;
          }
          reject(new Error(stderr.trim() || `pip exited with code ${code}`));
        });
      })
  );
}
