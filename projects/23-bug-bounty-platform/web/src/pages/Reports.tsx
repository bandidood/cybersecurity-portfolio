import { useState } from 'react';
import { Download, FileText, Calendar } from 'lucide-react';

interface Report {
  id: string;
  title: string;
  type: 'vulnerability' | 'program';
  generatedDate: string;
  format: 'PDF' | 'HTML' | 'Markdown';
  size: string;
}

export function Reports() {
  const reports: Report[] = [
    {
      id: 'RPT-001',
      title: 'SQL Injection Vulnerability Report - Acme Corp',
      type: 'vulnerability',
      generatedDate: '2024-01-15',
      format: 'PDF',
      size: '245 KB',
    },
    {
      id: 'RPT-002',
      title: 'XSS Vulnerability Report - Tech Startup',
      type: 'vulnerability',
      generatedDate: '2024-01-20',
      format: 'HTML',
      size: '128 KB',
    },
    {
      id: 'RPT-003',
      title: 'Monthly Program Summary - January 2024',
      type: 'program',
      generatedDate: '2024-02-01',
      format: 'PDF',
      size: '512 KB',
    },
    {
      id: 'RPT-004',
      title: 'CSRF Vulnerability Report - E-commerce Platform',
      type: 'vulnerability',
      generatedDate: '2024-01-18',
      format: 'Markdown',
      size: '64 KB',
    },
  ];

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
        <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
          <FileText className="h-5 w-5 mr-2" />
          Generate New Report
        </button>
      </div>

      {/* Report Generation Options */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Generate Custom Report</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report Type
            </label>
            <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
              <option>Vulnerability Report</option>
              <option>Program Summary</option>
              <option>Monthly Activity</option>
              <option>Earnings Report</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Format
            </label>
            <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
              <option>PDF</option>
              <option>HTML</option>
              <option>Markdown</option>
              <option>JSON</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Period
            </label>
            <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
              <option>Last 7 Days</option>
              <option>Last 30 Days</option>
              <option>Last 3 Months</option>
              <option>Last Year</option>
              <option>All Time</option>
            </select>
          </div>
        </div>
        <div className="mt-4">
          <button className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
            Generate Report
          </button>
        </div>
      </div>

      {/* Reports List */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Generated Reports</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {reports.map((report) => (
            <div key={report.id} className="px-6 py-4 hover:bg-gray-50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-1">
                    <FileText className="h-5 w-5 text-gray-400" />
                    <h3 className="text-sm font-medium text-gray-900">{report.title}</h3>
                  </div>
                  <div className="flex items-center space-x-4 text-xs text-gray-500">
                    <span className={`px-2 py-1 rounded ${
                      report.type === 'vulnerability'
                        ? 'bg-purple-100 text-purple-800'
                        : 'bg-blue-100 text-blue-800'
                    }`}>
                      {report.type === 'vulnerability' ? 'Vulnerability' : 'Program Summary'}
                    </span>
                    <span className="flex items-center">
                      <Calendar className="h-3 w-3 mr-1" />
                      {new Date(report.generatedDate).toLocaleDateString()}
                    </span>
                    <span>{report.format}</span>
                    <span>{report.size}</span>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors">
                    <Download className="h-5 w-5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Report Templates */}
      <div className="mt-6 bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Report Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <TemplateCard
            title="Vulnerability Report"
            description="Comprehensive vulnerability documentation with CVSS scoring"
            formats={['PDF', 'HTML', 'Markdown']}
          />
          <TemplateCard
            title="Program Summary"
            description="Bug bounty program statistics and performance metrics"
            formats={['PDF', 'HTML']}
          />
          <TemplateCard
            title="Earnings Report"
            description="Detailed breakdown of rewards and payouts"
            formats={['PDF', 'JSON']}
          />
        </div>
      </div>
    </div>
  );
}

interface TemplateCardProps {
  title: string;
  description: string;
  formats: string[];
}

function TemplateCard({ title, description, formats }: TemplateCardProps) {
  return (
    <div className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
      <h3 className="font-semibold text-gray-900 mb-2">{title}</h3>
      <p className="text-sm text-gray-600 mb-3">{description}</p>
      <div className="flex flex-wrap gap-2">
        {formats.map((format) => (
          <span
            key={format}
            className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded"
          >
            {format}
          </span>
        ))}
      </div>
    </div>
  );
}
