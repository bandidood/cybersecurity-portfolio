/**
 * Utility functions for formatting data, dates, numbers, etc.
 */

import { format, formatDistance, formatRelative } from 'date-fns';

// ==================== Date Formatting ====================

export const formatDate = (date: string | Date, formatStr: string = 'PPpp'): string => {
  try {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return format(dateObj, formatStr);
  } catch (error) {
    return 'Invalid date';
  }
};

export const formatRelativeTime = (date: string | Date): string => {
  try {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return formatDistance(dateObj, new Date(), { addSuffix: true });
  } catch (error) {
    return 'Invalid date';
  }
};

export const formatRelativeDate = (date: string | Date): string => {
  try {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    return formatRelative(dateObj, new Date());
  } catch (error) {
    return 'Invalid date';
  }
};

// ==================== Number Formatting ====================

export const formatNumber = (value: number, decimals: number = 0): string => {
  return value.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
};

export const formatPercentage = (value: number, decimals: number = 1): string => {
  return `${(value * 100).toFixed(decimals)}%`;
};

export const formatBytes = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
};

// ==================== Security-Specific Formatting ====================

export const formatSeverity = (severity: string): string => {
  const severityMap: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  };
  return severityMap[severity.toLowerCase()] || severity;
};

export const getSeverityColor = (severity: string): string => {
  const colorMap: Record<string, string> = {
    critical: '#ff1744',
    high: '#ff6b35',
    medium: '#ffa726',
    low: '#29b6f6',
    info: '#4caf50',
  };
  return colorMap[severity.toLowerCase()] || '#9ca3af';
};

export const formatIPAddress = (ip: string): string => {
  // Basic IP validation and formatting
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipRegex.test(ip) ? ip : 'Invalid IP';
};

export const maskSensitiveData = (data: string, visibleChars: number = 4): string => {
  if (data.length <= visibleChars) return data;
  const masked = '*'.repeat(data.length - visibleChars);
  return masked + data.slice(-visibleChars);
};

export const truncateHash = (hash: string, length: number = 8): string => {
  if (hash.length <= length * 2) return hash;
  return `${hash.slice(0, length)}...${hash.slice(-length)}`;
};

// ==================== Status Formatting ====================

export const formatStatus = (status: string): { label: string; color: string } => {
  const statusMap: Record<string, { label: string; color: string }> = {
    active: { label: 'Active', color: '#4caf50' },
    inactive: { label: 'Inactive', color: '#9ca3af' },
    pending: { label: 'Pending', color: '#ffa726' },
    resolved: { label: 'Resolved', color: '#4caf50' },
    investigating: { label: 'Investigating', color: '#29b6f6' },
    blocked: { label: 'Blocked', color: '#ff1744' },
  };
  return statusMap[status.toLowerCase()] || { label: status, color: '#9ca3af' };
};

// ==================== Text Formatting ====================

export const capitalize = (str: string): string => {
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const truncate = (str: string, maxLength: number, suffix: string = '...'): string => {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - suffix.length) + suffix;
};

export const slugify = (str: string): string => {
  return str
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

export default {
  formatDate,
  formatRelativeTime,
  formatRelativeDate,
  formatNumber,
  formatPercentage,
  formatBytes,
  formatSeverity,
  getSeverityColor,
  formatIPAddress,
  maskSensitiveData,
  truncateHash,
  formatStatus,
  capitalize,
  truncate,
  slugify,
};
