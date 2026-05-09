import * as path from 'path';
import * as vscode from 'vscode';

import { Finding, Severity } from './types';

type TreeNode = SeverityGroupNode | FindingNode;

const severityOrder: Severity[] = ['block', 'critical', 'warning', 'info'];

function severityIcon(severity: Severity): vscode.ThemeIcon {
  switch (severity) {
    case 'block':
      return new vscode.ThemeIcon('error', new vscode.ThemeColor('problemsErrorIcon.foreground'));
    case 'critical':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsErrorIcon.foreground'));
    case 'warning':
      return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
    default:
      return new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
  }
}

class SeverityGroupNode extends vscode.TreeItem {
  constructor(
    public readonly severity: Severity,
    public readonly findings: Finding[]
  ) {
    super(`${severity.toUpperCase()} (${findings.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = severityIcon(severity);
    this.contextValue = 'severity-group';
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    const basename = finding.location ? path.basename(finding.location.split(':')[0]) : finding.rule_id;
    super(`${finding.rule_id}  ${basename}`, vscode.TreeItemCollapsibleState.None);
    this.description = finding.description;
    this.tooltip = new vscode.MarkdownString(
      `**${finding.rule_id}**\n\n${finding.description}\n\n${finding.suggestion}\n\n${finding.location || 'workspace'}`
    );
    this.iconPath = severityIcon(finding.severity);
    this.command = {
      command: 'contractguard.openFinding',
      title: 'Open Finding',
      arguments: [finding]
    };
    this.contextValue = 'finding';
  }
}

export class FindingsTreeDataProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly emitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private findings: Finding[] = [];

  setFindings(findings: Finding[]): void {
    this.findings = findings;
    this.emitter.fire(undefined);
  }

  clear(): void {
    this.setFindings([]);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      return severityOrder
        .map((severity) => {
          const items = this.findings.filter((finding) => finding.severity === severity);
          return items.length > 0 ? new SeverityGroupNode(severity, items) : undefined;
        })
        .filter((node): node is SeverityGroupNode => Boolean(node));
    }

    if (element instanceof SeverityGroupNode) {
      return element.findings.map((finding) => new FindingNode(finding));
    }

    return [];
  }
}
