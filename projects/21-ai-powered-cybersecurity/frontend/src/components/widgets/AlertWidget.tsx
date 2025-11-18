import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
} from '@mui/material';
import { Warning, Error, Info, CheckCircle } from '@mui/icons-material';
import { formatRelativeTime } from '../../utils/formatters';

export interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  message: string;
  timestamp: string;
}

interface AlertWidgetProps {
  alerts: Alert[];
  title?: string;
  maxItems?: number;
}

const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case 'critical':
      return <Error sx={{ color: '#ff1744' }} />;
    case 'high':
      return <Warning sx={{ color: '#ff6b35' }} />;
    case 'medium':
      return <Warning sx={{ color: '#ffa726' }} />;
    case 'low':
      return <Info sx={{ color: '#29b6f6' }} />;
    default:
      return <CheckCircle sx={{ color: '#4caf50' }} />;
  }
};

const getSeverityColor = (severity: string): string => {
  const colors: Record<string, string> = {
    critical: '#ff1744',
    high: '#ff6b35',
    medium: '#ffa726',
    low: '#29b6f6',
    info: '#4caf50',
  };
  return colors[severity] || '#9ca3af';
};

const AlertWidget: React.FC<AlertWidgetProps> = ({
  alerts,
  title = 'Recent Alerts',
  maxItems = 5,
}) => {
  const displayAlerts = alerts.slice(0, maxItems);

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
        <List>
          {displayAlerts.map((alert) => (
            <ListItem
              key={alert.id}
              sx={{
                mb: 1,
                backgroundColor: '#162027',
                borderRadius: 1,
                borderLeft: `4px solid ${getSeverityColor(alert.severity)}`,
              }}
            >
              <ListItemIcon>{getSeverityIcon(alert.severity)}</ListItemIcon>
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="body2">{alert.title}</Typography>
                    <Chip
                      label={alert.severity.toUpperCase()}
                      size="small"
                      sx={{
                        backgroundColor: getSeverityColor(alert.severity),
                        color: '#fff',
                        fontSize: '0.7rem',
                      }}
                    />
                  </Box>
                }
                secondary={
                  <>
                    <Typography variant="caption" display="block">
                      {alert.message}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatRelativeTime(alert.timestamp)}
                    </Typography>
                  </>
                }
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default AlertWidget;
