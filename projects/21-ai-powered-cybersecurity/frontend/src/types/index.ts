// Core Types for AI-Powered Cybersecurity Platform
// Author: AI Cybersecurity Team
// Version: 1.0.0

export interface IOC {
  value: string;
  type: IOCType;
  first_seen: string;
  confidence: number;
  tags: string[];
  context?: IOCContext;
}

export type IOCType = 
  | 'ip_address' 
  | 'domain' 
  | 'url' 
  | 'email' 
  | 'md5' 
  | 'sha1' 
  | 'sha256' 
  | 'cve' 
  | 'file_path' 
  | 'registry_key' 
  | 'process_name' 
  | 'mutex'
  | 'bitcoin_address';

export interface IOCContext {
  geolocation?: string;
  asn?: string;
  reputation?: string;
  registrar?: string;
  creation_date?: string;
  dns_records?: string[];
  file_type?: string;
  size?: string;
  signature_status?: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  text: string;
  source?: string;
  severity: SeverityLevel;
  classification: LogClassification;
}

export interface LogAnalysisResult {
  entry_id: string;
  original_text: string;
  processed_text: string;
  analysis_timestamp: string;
  iocs: { [key in IOCType]?: string[] };
  entities: { [key: string]: EntityMatch[] };
  severity: SeverityAssessment;
  threat_analysis: ThreatAnalysis;
  ml_predictions?: MLPredictions;
}

export interface EntityMatch {
  text: string;
  start: number;
  end: number;
  confidence: number;
}

export interface SeverityAssessment {
  severity: SeverityLevel;
  confidence: number;
  scores: { [key in SeverityLevel]: number };
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface ThreatAnalysis {
  threat_level: ThreatLevel;
  total_score: number;
  indicators: {
    malware_score: number;
    attack_score: number;
    vulnerability_score: number;
    network_score: number;
    auth_score: number;
  };
}

export type ThreatLevel = 'high' | 'medium' | 'low';

export interface MLPredictions {
  log_type: {
    prediction: LogClassification;
    confidence: number;
  };
  priority: {
    prediction: PriorityLevel;
    confidence: number;
  };
}

export type LogClassification = 'normal' | 'security_event' | 'security_alert';
export type PriorityLevel = 'low' | 'medium' | 'high';

// Threat Intelligence Types
export interface ThreatIntelReport {
  id: string;
  title: string;
  content: string;
  source: string;
  timestamp: string;
  confidence: number;
}

export interface ThreatIntelAnalysis {
  report_id: string;
  original_text: string;
  processed_text: string;
  analysis_timestamp: string;
  iocs: { [key in IOCType]?: string[] };
  enriched_iocs: { [key in IOCType]?: { [ioc: string]: IOC } };
  ttps: TTP[];
  attribution: ThreatAttribution;
  malware_classification: MalwareClassification;
  ml_predictions?: ThreatMLPredictions;
}

export interface TTP {
  tactic: string;
  technique: string;
  technique_id: string;
  description: string;
  indicators: string[];
  confidence: number;
}

export interface ThreatAttribution {
  attributed_actor: string | null;
  confidence: number;
  all_scores: { [actor: string]: number };
  attribution_method: string;
}

export interface ThreatActor {
  name: string;
  aliases: string[];
  country: string;
  motivation: string;
  techniques: string[];
  indicators: string[];
  confidence: number;
}

export interface MalwareClassification {
  malware_family: MalwareFamily;
  confidence: number;
  all_scores: { [family in MalwareFamily]: number };
}

export type MalwareFamily = 
  | 'banking_trojan' 
  | 'ransomware' 
  | 'backdoor' 
  | 'apt_malware' 
  | 'commodity_malware' 
  | 'unknown';

export interface ThreatMLPredictions {
  report_type: {
    prediction: ThreatReportType;
    confidence: number;
  };
  intelligence_confidence: {
    prediction: ConfidenceLevel;
    confidence: number;
  };
  campaign_cluster: number;
}

export type ThreatReportType = 
  | 'apt_report' 
  | 'malware_analysis' 
  | 'phishing_campaign' 
  | 'threat_intelligence';

export type ConfidenceLevel = 'low' | 'medium' | 'high' | 'very_high';

// Incident Analysis Types
export interface SecurityIncident {
  incident_id: string;
  analysis_timestamp: string;
  log_analysis: LogAnalysisResult[];
  threat_intelligence: ThreatIntelAnalysis[];
  correlation: IncidentCorrelation;
  recommendations: SecurityRecommendation[];
}

export interface IncidentCorrelation {
  shared_iocs: string[];
  threat_actor_mentions: ThreatActorMention[];
  technique_overlap: string[];
  severity_correlation: { [key: string]: any };
  confidence_score: number;
}

export interface ThreatActorMention {
  actor: string;
  log_entry: string;
  confidence: number;
}

export interface SecurityRecommendation {
  priority: RecommendationPriority;
  category: string;
  action: string;
  details: string;
}

export type RecommendationPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// UI State Types
export interface DashboardMetrics {
  total_logs_analyzed: number;
  high_severity_events: number;
  iocs_extracted: number;
  threat_actors_identified: number;
  correlation_confidence: number;
  processing_time_ms: number;
}

export interface ChartData {
  name: string;
  value: number;
  color?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  category?: string;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: string;
  value: number;
  color?: string;
}

export interface NetworkEdge {
  source: string;
  target: string;
  value: number;
  type: string;
}

// API Response Types
export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
  errors?: string[];
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// File Upload Types
export interface FileUpload {
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'processing' | 'completed' | 'error';
  result?: LogAnalysisResult | ThreatIntelAnalysis;
  error?: string;
}

// Filter Types
export interface LogFilter {
  severity?: SeverityLevel[];
  classification?: LogClassification[];
  date_range?: {
    start: string;
    end: string;
  };
  ioc_types?: IOCType[];
  search_query?: string;
}

export interface ThreatIntelFilter {
  confidence_min?: number;
  threat_actors?: string[];
  malware_families?: MalwareFamily[];
  ttps?: string[];
  date_range?: {
    start: string;
    end: string;
  };
  search_query?: string;
}

// Theme and UI Types
export interface ThemeConfig {
  mode: 'light' | 'dark';
  primaryColor: string;
  secondaryColor: string;
  accentColor: string;
}

export interface NotificationState {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

// Store Types
export interface AppState {
  user: UserState | null;
  theme: ThemeConfig;
  notifications: NotificationState[];
  loading: boolean;
  error: string | null;
}

export interface UserState {
  id: string;
  username: string;
  email: string;
  role: 'analyst' | 'admin' | 'viewer';
  preferences: UserPreferences;
}

export interface UserPreferences {
  dashboard_layout: string[];
  default_filters: {
    logs: LogFilter;
    threat_intel: ThreatIntelFilter;
  };
  notifications_enabled: boolean;
  auto_refresh_interval: number;
}

// Analysis State Types
export interface AnalysisState {
  logs: {
    entries: LogEntry[];
    results: LogAnalysisResult[];
    filters: LogFilter;
    loading: boolean;
    error: string | null;
  };
  threatIntel: {
    reports: ThreatIntelReport[];
    results: ThreatIntelAnalysis[];
    filters: ThreatIntelFilter;
    loading: boolean;
    error: string | null;
  };
  incidents: {
    current: SecurityIncident | null;
    history: SecurityIncident[];
    loading: boolean;
    error: string | null;
  };
}

// Component Props Types
export interface BaseComponentProps {
  className?: string;
  style?: React.CSSProperties;
}

export interface CardProps extends BaseComponentProps {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  loading?: boolean;
  error?: string | null;
}

export interface DataTableProps<T> extends BaseComponentProps {
  data: T[];
  columns: TableColumn<T>[];
  loading?: boolean;
  pagination?: boolean;
  sortable?: boolean;
  filterable?: boolean;
  selectable?: boolean;
  onRowClick?: (row: T) => void;
  onSelectionChange?: (selected: T[]) => void;
}

export interface TableColumn<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  filterable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
  width?: number;
  align?: 'left' | 'center' | 'right';
}