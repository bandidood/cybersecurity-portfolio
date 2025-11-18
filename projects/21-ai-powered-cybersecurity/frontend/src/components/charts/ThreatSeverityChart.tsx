import React from 'react';
import { Box, Card, CardContent, Typography } from '@mui/material';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface ThreatData {
  name: string;
  value: number;
  color: string;
}

interface ThreatSeverityChartProps {
  data?: ThreatData[];
  title?: string;
}

const DEFAULT_DATA: ThreatData[] = [
  { name: 'Critical', value: 12, color: '#ff1744' },
  { name: 'High', value: 28, color: '#ff6b35' },
  { name: 'Medium', value: 45, color: '#ffa726' },
  { name: 'Low', value: 89, color: '#29b6f6' },
  { name: 'Info', value: 126, color: '#4caf50' },
];

const ThreatSeverityChart: React.FC<ThreatSeverityChartProps> = ({
  data = DEFAULT_DATA,
  title = 'Threat Distribution by Severity',
}) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        <Box sx={{ height: 300 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Box>
      </CardContent>
    </Card>
  );
};

export default ThreatSeverityChart;
