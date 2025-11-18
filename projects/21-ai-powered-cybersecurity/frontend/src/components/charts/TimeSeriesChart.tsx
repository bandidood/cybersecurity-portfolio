import React from 'react';
import { Box, Card, CardContent, Typography } from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

interface TimeSeriesData {
  time: string;
  [key: string]: string | number;
}

interface TimeSeriesChartProps {
  data: TimeSeriesData[];
  title?: string;
  dataKeys?: string[];
  colors?: string[];
}

const DEFAULT_COLORS = ['#00d4ff', '#ff6b35', '#4caf50', '#ffa726', '#ff1744'];

const TimeSeriesChart: React.FC<TimeSeriesChartProps> = ({
  data,
  title = 'Time Series Analysis',
  dataKeys = ['value'],
  colors = DEFAULT_COLORS,
}) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        <Box sx={{ height: 300 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2e35" />
              <XAxis dataKey="time" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#162027',
                  border: '1px solid #2a2e35',
                  borderRadius: '4px',
                }}
              />
              <Legend />
              {dataKeys.map((key, index) => (
                <Line
                  key={key}
                  type="monotone"
                  dataKey={key}
                  stroke={colors[index % colors.length]}
                  strokeWidth={2}
                  dot={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </Box>
      </CardContent>
    </Card>
  );
};

export default TimeSeriesChart;
