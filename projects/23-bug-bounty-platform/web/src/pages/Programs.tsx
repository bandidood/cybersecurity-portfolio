import { useState } from 'react';
import { DollarSign, Users, Calendar, ExternalLink } from 'lucide-react';

interface Program {
  id: string;
  name: string;
  company: string;
  rewards: string;
  scope: string[];
  status: 'Active' | 'Inactive';
  participants: number;
  launchedDate: string;
}

export function Programs() {
  const programs: Program[] = [
    {
      id: 'prog-001',
      name: 'Acme Corp Bug Bounty',
      company: 'Acme Corporation',
      rewards: '$500 - $10,000',
      scope: ['*.acme.com', 'api.acme.com', 'mobile apps'],
      status: 'Active',
      participants: 1250,
      launchedDate: '2023-06-15',
    },
    {
      id: 'prog-002',
      name: 'Tech Startup Program',
      company: 'Tech Innovations Inc',
      rewards: '$200 - $5,000',
      scope: ['webapp.techinc.io', 'api.techinc.io'],
      status: 'Active',
      participants: 450,
      launchedDate: '2023-09-01',
    },
    {
      id: 'prog-003',
      name: 'E-commerce Platform',
      company: 'ShopSmart Ltd',
      rewards: '$1,000 - $15,000',
      scope: ['*.shopsmart.com', 'checkout.shopsmart.com', 'admin.shopsmart.com'],
      status: 'Active',
      participants: 2100,
      launchedDate: '2023-01-10',
    },
    {
      id: 'prog-004',
      name: 'SaaS Company Security',
      company: 'CloudApps Co',
      rewards: '$300 - $7,500',
      scope: ['app.cloudapps.io', '*.cloudapps.io'],
      status: 'Active',
      participants: 890,
      launchedDate: '2023-11-20',
    },
  ];

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Bug Bounty Programs</h1>
        <div className="text-sm text-gray-600">
          {programs.filter(p => p.status === 'Active').length} Active Programs
        </div>
      </div>

      {/* Programs Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {programs.map((program) => (
          <ProgramCard key={program.id} program={program} />
        ))}
      </div>
    </div>
  );
}

interface ProgramCardProps {
  program: Program;
}

function ProgramCard({ program }: ProgramCardProps) {
  return (
    <div className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow">
      <div className="p-6">
        {/* Header */}
        <div className="flex justify-between items-start mb-4">
          <div className="flex-1">
            <h3 className="text-xl font-bold text-gray-900 mb-1">{program.name}</h3>
            <p className="text-sm text-gray-600">{program.company}</p>
          </div>
          <span className={`px-3 py-1 text-xs font-semibold rounded-full ${
            program.status === 'Active'
              ? 'bg-green-100 text-green-800'
              : 'bg-gray-100 text-gray-800'
          }`}>
            {program.status}
          </span>
        </div>

        {/* Rewards */}
        <div className="flex items-center mb-4 p-3 bg-blue-50 rounded-lg">
          <DollarSign className="h-5 w-5 text-blue-600 mr-2" />
          <div>
            <div className="text-xs text-gray-600">Reward Range</div>
            <div className="text-sm font-semibold text-gray-900">{program.rewards}</div>
          </div>
        </div>

        {/* Scope */}
        <div className="mb-4">
          <div className="text-xs font-medium text-gray-600 mb-2">Scope</div>
          <div className="flex flex-wrap gap-2">
            {program.scope.map((item, index) => (
              <span
                key={index}
                className="px-2 py-1 text-xs font-mono bg-gray-100 text-gray-700 rounded"
              >
                {item}
              </span>
            ))}
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center justify-between text-sm text-gray-600 mb-4">
          <div className="flex items-center">
            <Users className="h-4 w-4 mr-1" />
            <span>{program.participants} researchers</span>
          </div>
          <div className="flex items-center">
            <Calendar className="h-4 w-4 mr-1" />
            <span>Since {new Date(program.launchedDate).toLocaleDateString()}</span>
          </div>
        </div>

        {/* Action Button */}
        <button className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center">
          View Program Details
          <ExternalLink className="h-4 w-4 ml-2" />
        </button>
      </div>
    </div>
  );
}
