/**
 * Aegis Journal - Application Type Definitions
 */

export interface UserProfile {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  userAliases?: string[];
}

export interface RedactionSummary {
  counts: Record<string, number>;
  categories: string[];
}

export interface EntryMessage {
  id: string;
  role: 'user' | 'model';
  text: string;
  rehydratedText?: string;
  modelUsed?: string;
  createdAt: string;
}

export interface JournalEntry {
  id: string;
  title: string;
  redactedContent: string;
  rehydratedContent?: string;
  redactionSummary: RedactionSummary;
  createdAt: string;
  updatedAt?: string;
  messageCount?: number;
  messages?: EntryMessage[];
}

export interface RedactionInspectionItem {
  raw: string;
  tokenized: string;
  category: string;
  token: string;
}

export interface CustodyStatus {
  runtimeEnvironment: string;
  serverBoundKey: boolean;
  clientKeyExposure: boolean;
  keyConfigured: boolean;
  keyMask: string;
  databaseId: string;
  isolationModel: string;
  piiRedactionGateway: string;
  checkedAt: string;
}

export interface InjectionTestResult {
  success: boolean;
  adversarialInput: string;
  neutralized: boolean;
  modelUsed: string;
  reflectionResponse: string;
  defenseMechanism: string;
  timestamp: string;
}

export interface AuditLogItem {
  id: string;
  action: string;
  ts: any;
  metadata?: Record<string, any>;
}
