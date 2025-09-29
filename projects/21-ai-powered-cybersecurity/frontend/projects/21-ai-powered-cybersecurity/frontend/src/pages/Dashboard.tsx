import React from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Button,
} from '@mui/material';
import {
  TrendingUp,
  TrendingDown,
  Warning,
  Security,
  Speed,
  Assessment,
  Visibility,
  MoreVert,
  PlayArrow,
  Refresh,
} from '@mui/icons-material';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
} from 'recharts';

// Mock data for demonstrations
const threatLevelData = [
  { name: '00:00', threats: 12, incidents: 2 },
  { name: '04:00', threats: 19, incidents: 3 },
  { name: '08:00', threats: 35, incidents: 8 },
  { name: '12:00', threats: 28, incidents: 5 },
  { name: '16:00', threats: 45, incidents: 12 },
  { name: '20:00', threats: 33, incidents: 7 },
];

const severityDistribution = [
  { name: 'Critical', value: 15, color: '#ff1744' },
  { name: 'High', value: 28, color: '#ff6b35' },
  { name: 'Medium', value: 42, color: '#ffa726' },
  { name: 'Low', value: 85, color: '#4caf50' },
];

const iocTypeData = [
  { type: 'IP Address', count: 142 },
  { type: 'Domain', count: 89 },
  { type: 'Hash', count: 67 },
  { type: 'URL', count: 45 },
  { type: 'Email', count: 23 },
];

const recentAlerts = [
  {
    id: '1',
    severity: 'critical',
    title: 'Ransomware Activity Detected',
    description: 'Suspicious file encryption behavior on HOST-SERVER01',
    timestamp: '2 minutes ago',
    iocs: 3,
  },
  {
    id: '2',
    severity: 'high',
    title: 'APT29 IOCs Identified',
    description: 'Known threat actor indicators found in network traffic',
    timestamp: '15 minutes ago',
    iocs: 7,
  },
  {
    id: '3',
    severity: 'medium',
    title: 'Phishing Campaign Detected',
    description: 'Malicious emails targeting healthcare sector',
    timestamp: '1 hour ago',
    iocs: 12,
  },
  {
    id: '4',
    severity: 'high',
    title: 'Lateral Movement Detected',
    description: 'Unusual network connections between systems',
    timestamp: '2 hours ago',
    iocs: 5,
  },
];

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return '#ff1744';
    case 'high': return '#ff6b35';
    case 'medium': return '#ffa726';
    case 'low': return '#4caf50';
    default: return '#9ca3af';
  }
};

const MetricCard: React.FC<{
  title: string;
  value: string | number;
  change?: number;
  icon: React.ReactNode;
  color?: string;
}> = ({ title, value, change, icon, color = 'primary.main' }) => (
  <Card>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography color="textSecondary" gutterBottom variant="overline">
            {title}
          </Typography>
          <Typography variant="h4" component="div" sx={{ color, fontWeight: 700 }}>
            {value}
          </Typography>
          {change !== undefined && (
            <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
              {change >= 0 ? (
                <TrendingUp sx={{ color: 'success.main', fontSize: 18 }} />
              ) : (
                <TrendingDown sx={{ color: 'error.main', fontSize: 18 }} />
              )}
              <Typography
                variant="body2"
                color={change >= 0 ? 'success.main' : 'error.main'}
                sx={{ ml: 0.5 }}
              >
                {Math.abs(change)}% vs last week
              </Typography>
            </Box>
          )}
        </Box>
        <Box sx={{ color, opacity: 0.7 }}>
          {icon}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

const Dashboard: React.FC = () => {
  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
            Security Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Real-time threat monitoring and analysis powered by AI
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button variant="outlined" startIcon={<Refresh />}>
            Refresh
          </Button>
          <Button variant="contained" startIcon={<PlayArrow />}>
            Start Analysis
          </Button>
        </Box>
      </Box>

      {/* Key Metrics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Threats Detected"
            value={245}
            change={12}
            icon={<Security sx={{ fontSize: 40 }} />}
            color="#ff6b35"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="IOCs Extracted"
            value={1847}
            change={-5}
            icon={<Visibility sx={{ fontSize: 40 }} />}
            color="#00d4ff"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Processing Speed"
            value="156ms"
            change={23}
            icon={<Speed sx={{ fontSize: 40 }} />}
            color="#4caf50"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Model Accuracy"
            value="94.7%"
            change={2}
            icon={<Assessment sx={{ fontSize: 40 }} />}
            color="#ffa726"
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Threat Trends Chart */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6" component="h2">
                  Threat Activity Timeline
                </Typography>
                <IconButton size="small">
                  <MoreVert />
                </IconButton>
              </Box>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={threatLevelData}>
                  <defs>
                    <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff6b35" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ff6b35" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="incidentsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.1)" />
                  <XAxis dataKey="name" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#162027',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#ff6b35"
                    fillOpacity={1}
                    fill="url(#threatsGradient)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="incidents"
                    stroke="#00d4ff"
                    fillOpacity={1}
                    fill="url(#incidentsGradient)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Severity Distribution */}
        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                Threat Severity Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    stroke="none"
                  >
                    {severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#162027',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 2 }}>
                {severityDistribution.map((item) => (
                  <Chip
                    key={item.name}
                    label={`${item.name}: ${item.value}`}
                    size="small"
                    sx={{
                      bgcolor: `${item.color}20`,
                      color: item.color,
                      border: `1px solid ${item.color}40`,
                    }}
                  />
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* IOC Types */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                IOC Types Detected
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={iocTypeData} margin={{ left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.1)" />
                  <XAxis dataKey="type" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#162027',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Alerts */}
        <Grid item xs={12} lg={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" component="h2">
                  Recent Security Alerts
                </Typography>
                <Button size="small" variant="text">
                  View All
                </Button>
              </Box>
              <List>
                {recentAlerts.map((alert) => (
                  <ListItem key={alert.id} sx={{ px: 0, py: 1 }}>
                    <ListItemIcon>
                      <Warning sx={{ color: getSeverityColor(alert.severity) }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {alert.title}
                          </Typography>
                          <Chip
                            label={alert.severity.toUpperCase()}
                            size="small"
                            sx={{
                              bgcolor: `${getSeverityColor(alert.severity)}20`,
                              color: getSeverityColor(alert.severity),
                              fontSize: '0.7rem',
                              height: 20,
                            }}
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                            {alert.description}
                          </Typography>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Typography variant="caption" color="text.secondary">
                              {alert.timestamp}
                            </Typography>
                            <Typography variant="caption" color="primary.main">
                              {alert.iocs} IOCs
                            </Typography>
                          </Box>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* System Health */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                System Health & Performance
              </Typography>
              <Grid container spacing={3}>
                <Grid item xs={12} md={3}>
                  <Box>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      CPU Usage
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={65}
                      sx={{ height: 8, borderRadius: 4, bgcolor: 'rgba(255, 255, 255, 0.1)' }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      65% - Normal
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Box>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Memory Usage
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={78}
                      sx={{ height: 8, borderRadius: 4, bgcolor: 'rgba(255, 255, 255, 0.1)' }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      78% - Normal
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Box>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Model Performance
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={94}
                      color="success"
                      sx={{ height: 8, borderRadius: 4, bgcolor: 'rgba(255, 255, 255, 0.1)' }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      94% - Excellent
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={3}>
                  <Box>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Data Pipeline
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={100}
                      color="success"
                      sx={{ height: 8, borderRadius: 4, bgcolor: 'rgba(255, 255, 255, 0.1)' }}
                    />
                    <Typography variant="caption" color="text.secondary">
                      100% - Operational
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;