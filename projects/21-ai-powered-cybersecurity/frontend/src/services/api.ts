/**
 * API Service - Centralized API client for AI Cybersecurity Platform
 * Handles all HTTP requests to the FastAPI backend
 */

import axios, { AxiosInstance, AxiosError, AxiosResponse } from 'axios';
import { toast } from 'react-hot-toast';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT || '30000', 10);

// Create axios instance with default configuration
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - Add auth token, logging, etc.
apiClient.interceptors.request.use(
  (config) => {
    // Add authorization token if available
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Log request in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[API Request] ${config.method?.toUpperCase()} ${config.url}`, config.data);
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - Handle errors globally
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    // Log response in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[API Response] ${response.config.url}`, response.data);
    }
    return response;
  },
  (error: AxiosError) => {
    // Handle different error scenarios
    if (error.response) {
      // Server responded with error status
      const status = error.response.status;
      const message = (error.response.data as any)?.message || error.message;

      switch (status) {
        case 401:
          toast.error('Unauthorized - Please log in');
          // Redirect to login or refresh token
          break;
        case 403:
          toast.error('Access forbidden');
          break;
        case 404:
          toast.error('Resource not found');
          break;
        case 500:
          toast.error('Server error - Please try again later');
          break;
        default:
          toast.error(message || 'An error occurred');
      }
    } else if (error.request) {
      // Request made but no response
      toast.error('Network error - Please check your connection');
    } else {
      // Error in request configuration
      toast.error('Request error');
    }

    return Promise.reject(error);
  }
);

// ==================== API Endpoints ====================

export const api = {
  // Health Check
  health: {
    check: () => apiClient.get('/health'),
    metrics: () => apiClient.get('/health/metrics'),
  },

  // Log Analysis
  logs: {
    analyze: (logData: string | string[]) =>
      apiClient.post('/api/logs/analyze', { logs: logData }),
    batch: (logs: any[]) =>
      apiClient.post('/api/logs/batch', { logs }),
    anomalies: (params?: { start_date?: string; end_date?: string }) =>
      apiClient.get('/api/logs/anomalies', { params }),
    statistics: () =>
      apiClient.get('/api/logs/statistics'),
  },

  // Threat Intelligence
  threatIntel: {
    analyze: (text: string) =>
      apiClient.post('/api/threat-intel/analyze', { text }),
    iocs: (params?: { type?: string; severity?: string }) =>
      apiClient.get('/api/threat-intel/iocs', { params }),
    enrich: (indicator: string, indicatorType: string) =>
      apiClient.post('/api/threat-intel/enrich', {
        indicator,
        indicator_type: indicatorType,
      }),
    feeds: () =>
      apiClient.get('/api/threat-intel/feeds'),
  },

  // Incident Analysis
  incidents: {
    list: (params?: { status?: string; severity?: string; limit?: number }) =>
      apiClient.get('/api/incidents', { params }),
    get: (incidentId: string) =>
      apiClient.get(`/api/incidents/${incidentId}`),
    create: (incidentData: any) =>
      apiClient.post('/api/incidents', incidentData),
    update: (incidentId: string, updates: any) =>
      apiClient.patch(`/api/incidents/${incidentId}`, updates),
    analyze: (incidentId: string) =>
      apiClient.post(`/api/incidents/${incidentId}/analyze`),
    timeline: (incidentId: string) =>
      apiClient.get(`/api/incidents/${incidentId}/timeline`),
  },

  // ML Models
  models: {
    list: () =>
      apiClient.get('/api/models'),
    predict: (modelName: string, features: any) =>
      apiClient.post(`/api/models/${modelName}/predict`, { features }),
    performance: (modelName: string) =>
      apiClient.get(`/api/models/${modelName}/performance`),
    retrain: (modelName: string, data?: any) =>
      apiClient.post(`/api/models/${modelName}/retrain`, data),
  },

  // User & Network Behavior Analytics
  analytics: {
    userRisk: (userId: string) =>
      apiClient.get(`/api/analytics/user-risk/${userId}`),
    networkAnomaly: (params?: { start_time?: string; end_time?: string }) =>
      apiClient.get('/api/analytics/network-anomaly', { params }),
    behaviorProfile: (entityId: string, entityType: 'user' | 'host') =>
      apiClient.get(`/api/analytics/behavior/${entityType}/${entityId}`),
  },

  // Reports & Export
  reports: {
    generate: (reportType: string, params: any) =>
      apiClient.post('/api/reports/generate', { report_type: reportType, params }),
    download: (reportId: string) =>
      apiClient.get(`/api/reports/${reportId}/download`, { responseType: 'blob' }),
    list: (params?: { type?: string; start_date?: string; end_date?: string }) =>
      apiClient.get('/api/reports', { params }),
  },

  // Settings & Configuration
  settings: {
    get: () =>
      apiClient.get('/api/settings'),
    update: (settings: any) =>
      apiClient.put('/api/settings', settings),
    reset: () =>
      apiClient.post('/api/settings/reset'),
  },
};

// Export axios instance for custom requests
export { apiClient };

export default api;
