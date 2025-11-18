import { useEffect, useState } from 'react';
import { TrendingUp, AlertCircle, DollarSign, Award } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

interface Stats {
  totalSubmissions: number;
  acceptedSubmissions: number;
  totalEarnings: number;
  currentRank: number;
}

export function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalSubmissions: 24,
    acceptedSubmissions: 18,
    totalEarnings: 12500,
    currentRank: 42,
  });

  const severityData = [
    { name: 'Critical', value: 3, color: '#ef4444' },
    { name: 'High', value: 7, color: '#f97316' },
    { name: 'Medium', value: 6, color: '#f59e0b' },
    { name: 'Low', value: 2, color: '#10b981' },
  ];

  const monthlyData = [
    { month: 'Jan', submissions: 4, accepted: 3 },
    { month: 'Feb', submissions: 3, accepted: 2 },
    { month: 'Mar', submissions: 5, accepted: 4 },
    { month: 'Apr', submissions: 6, accepted: 5 },
    { month: 'May', submissions: 4, accepted: 3 },
    { month: 'Jun', submissions: 2, accepted: 1 },
  ];

  return (
    <div>
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Dashboard</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Total Submissions"
          value={stats.totalSubmissions}
          icon={AlertCircle}
          color="blue"
        />
        <StatCard
          title="Accepted"
          value={stats.acceptedSubmissions}
          icon={Award}
          color="green"
        />
        <StatCard
          title="Total Earnings"
          value={`$${stats.totalEarnings.toLocaleString()}`}
          icon={DollarSign}
          color="purple"
        />
        <StatCard
          title="Current Rank"
          value={`#${stats.currentRank}`}
          icon={TrendingUp}
          color="orange"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monthly Activity */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Monthly Activity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={monthlyData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="month" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="submissions" fill="#3b82f6" name="Submissions" />
              <Bar dataKey="accepted" fill="#10b981" name="Accepted" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Submissions */}
      <div className="mt-8 bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Recent Submissions</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {[
            { id: 'VUL-2024-001', title: 'SQL Injection in User Search', severity: 'Critical', status: 'Accepted', reward: 5000 },
            { id: 'VUL-2024-002', title: 'XSS in Comment System', severity: 'High', status: 'Under Review', reward: 0 },
            { id: 'VUL-2024-003', title: 'CSRF in Password Reset', severity: 'Medium', status: 'Accepted', reward: 1500 },
          ].map((submission) => (
            <div key={submission.id} className="px-6 py-4 hover:bg-gray-50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-mono text-gray-500">{submission.id}</span>
                    <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(submission.severity)}`}>
                      {submission.severity}
                    </span>
                  </div>
                  <h3 className="mt-1 text-sm font-medium text-gray-900">{submission.title}</h3>
                </div>
                <div className="flex items-center space-x-4">
                  <span className="text-sm text-gray-600">{submission.status}</span>
                  {submission.reward > 0 && (
                    <span className="text-sm font-semibold text-green-600">
                      ${submission.reward.toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  color: 'blue' | 'green' | 'purple' | 'orange';
}

function StatCard({ title, value, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600',
    green: 'bg-green-50 text-green-600',
    purple: 'bg-purple-50 text-purple-600',
    orange: 'bg-orange-50 text-orange-600',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon className="h-6 w-6" />
        </div>
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
