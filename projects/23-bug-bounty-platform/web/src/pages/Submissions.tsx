import { useState } from 'react';
import { Search, Filter, Plus } from 'lucide-react';

interface Submission {
  id: string;
  title: string;
  program: string;
  severity: string;
  status: string;
  submittedDate: string;
  reward: number;
}

export function Submissions() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');

  const submissions: Submission[] = [
    {
      id: 'VUL-2024-001',
      title: 'SQL Injection in User Search Endpoint',
      program: 'Acme Corp Bug Bounty',
      severity: 'Critical',
      status: 'Accepted',
      submittedDate: '2024-01-15',
      reward: 5000,
    },
    {
      id: 'VUL-2024-002',
      title: 'Cross-Site Scripting in Comment System',
      program: 'Tech Startup Program',
      severity: 'High',
      status: 'Under Review',
      submittedDate: '2024-01-20',
      reward: 0,
    },
    {
      id: 'VUL-2024-003',
      title: 'CSRF Vulnerability in Password Reset',
      program: 'E-commerce Platform',
      severity: 'Medium',
      status: 'Accepted',
      submittedDate: '2024-01-18',
      reward: 1500,
    },
    {
      id: 'VUL-2024-004',
      title: 'Information Disclosure via Error Messages',
      program: 'Acme Corp Bug Bounty',
      severity: 'Low',
      status: 'Duplicate',
      submittedDate: '2024-01-22',
      reward: 0,
    },
    {
      id: 'VUL-2024-005',
      title: 'Authentication Bypass in API',
      program: 'SaaS Company Security',
      severity: 'Critical',
      status: 'In Triage',
      submittedDate: '2024-01-25',
      reward: 0,
    },
  ];

  const filteredSubmissions = submissions.filter((sub) => {
    const matchesSearch = sub.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         sub.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterStatus === 'all' || sub.status === filterStatus;
    return matchesSearch && matchesFilter;
  });

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900">My Submissions</h1>
        <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center">
          <Plus className="h-5 w-5 mr-2" />
          New Submission
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <div className="flex flex-col sm:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search submissions..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          {/* Status Filter */}
          <div className="sm:w-48">
            <select
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
            >
              <option value="all">All Status</option>
              <option value="Accepted">Accepted</option>
              <option value="Under Review">Under Review</option>
              <option value="In Triage">In Triage</option>
              <option value="Duplicate">Duplicate</option>
              <option value="Rejected">Rejected</option>
            </select>
          </div>
        </div>
      </div>

      {/* Submissions Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Program
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Submitted
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Reward
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredSubmissions.map((submission) => (
              <tr key={submission.id} className="hover:bg-gray-50 cursor-pointer">
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm font-mono text-gray-900">{submission.id}</span>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-gray-900">{submission.title}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-sm text-gray-600">{submission.program}</span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(submission.severity)}`}>
                    {submission.severity}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getStatusColor(submission.status)}`}>
                    {submission.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                  {new Date(submission.submittedDate).toLocaleDateString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {submission.reward > 0 ? (
                    <span className="text-sm font-semibold text-green-600">
                      ${submission.reward.toLocaleString()}
                    </span>
                  ) : (
                    <span className="text-sm text-gray-400">-</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredSubmissions.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-500">No submissions found</p>
          </div>
        )}
      </div>
    </div>
  );
}

function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    Critical: 'bg-red-100 text-red-800',
    High: 'bg-orange-100 text-orange-800',
    Medium: 'bg-yellow-100 text-yellow-800',
    Low: 'bg-green-100 text-green-800',
  };
  return colors[severity] || 'bg-gray-100 text-gray-800';
}

function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    Accepted: 'bg-green-100 text-green-800',
    'Under Review': 'bg-blue-100 text-blue-800',
    'In Triage': 'bg-purple-100 text-purple-800',
    Duplicate: 'bg-gray-100 text-gray-800',
    Rejected: 'bg-red-100 text-red-800',
  };
  return colors[status] || 'bg-gray-100 text-gray-800';
}
