import React, { useState } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Alert,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
} from '@mui/material';
import {
  Sync,
  CheckCircle,
  Warning,
  Error,
  Info,
  Timeline,
  Assessment,
  Security,
  Visibility,
  PlayArrow,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

// Mock correlation data
const mockCorrelationData = {
  incident_id: 'INC-20240115-001',
  analysis_timestamp: '2024-01-15T14:30:00Z',
  correlation: {
    shared_iocs: ['203.0.113.42', 'evil-domain.com', 'a1b2c3d4e5f6789012345'],
    threat_actor_mentions: [
      { actor: 'APT29', log_entry: 'LOG-001', confidence: 0.87 },
    ],
    confidence_score: 0.84,
  },
  recommendations: [
    {
      priority: 'HIGH',
      category: 'Incident Response',
      action: 'Investigate 3 high-severity log entries immediately',
      details: 'Critical security events detected requiring immediate attention',
    },
    {
      priority: 'HIGH',
      category: 'Threat Hunting',
      action: 'Initiate threat hunting for APT29 TTPs',
      details: 'Known threat actors detected in intelligence reports',
    },
    {
      priority: 'MEDIUM',
      category: 'IOC Management',
      action: 'Block/monitor 3 correlated IOCs',
      details: 'IOCs appear in both logs and threat intelligence',
    },
  ],
};

const getPriorityColor = (priority: string) => {
  switch (priority) {
    case 'CRITICAL': return 'error';
    case 'HIGH': return 'error';
    case 'MEDIUM': return 'warning';
    case 'LOW': return 'info';
    default: return 'default';
  }
};

const IncidentAnalysis: React.FC = () => {
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [hasResults, setHasResults] = useState(true); // Mock: showing results

  const handleStartAnalysis = () => {
    setAnalysisRunning(true);
    setTimeout(() => {
      setAnalysisRunning(false);
      setHasResults(true);
    }, 3000);
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
          Incident Analysis & Correlation
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Cross-reference security logs with threat intelligence for comprehensive incident analysis
        </Typography>
      </Box>

      {/* Control Panel */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Correlation Engine
            </Typography>
            <Button
              variant="contained"
              startIcon={<PlayArrow />}
              onClick={handleStartAnalysis}
              disabled={analysisRunning}
            >
              {analysisRunning ? 'Analyzing...' : 'Start Correlation Analysis'}
            </Button>
          </Box>
          
          {analysisRunning && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress />
              <Typography variant="body2" color="primary.main" sx={{ mt: 1 }}>
                Correlating logs with threat intelligence data...
              </Typography>
            </Box>
          )}

          <Typography variant="body2" color="text.secondary">
            Combine security log analysis with threat intelligence to identify patterns, attribute threats, and generate actionable recommendations.
          </Typography>
        </CardContent>
      </Card>

      {hasResults && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <Grid container spacing={3}>
            {/* Correlation Summary */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Incident Summary
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'rgba(0, 212, 255, 0.1)' }}>
                        <Typography variant="h4" color="primary.main">
                          {mockCorrelationData.correlation.shared_iocs.length}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Shared IOCs
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'rgba(255, 107, 53, 0.1)' }}>
                        <Typography variant="h4" color="secondary.main">
                          {mockCorrelationData.correlation.threat_actor_mentions.length}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Threat Actors
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'rgba(76, 175, 80, 0.1)' }}>
                        <Typography variant="h4" color="success.main">
                          {(mockCorrelationData.correlation.confidence_score * 100).toFixed(0)}%
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Confidence Score
                        </Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center', bgcolor: 'rgba(255, 167, 38, 0.1)' }}>
                        <Typography variant="h4" color="warning.main">
                          {mockCorrelationData.recommendations.length}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Recommendations
                        </Typography>
                      </Paper>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>

            {/* Shared IOCs */}
            <Grid item xs={12} lg={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Correlated IOCs
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Indicators found in both security logs and threat intelligence reports
                  </Typography>
                  <List>
                    {mockCorrelationData.correlation.shared_iocs.map((ioc, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <Security color="error" />
                        </ListItemIcon>
                        <ListItemText
                          primary={ioc}
                          secondary={
                            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                              <Chip label="Malicious" size="small" color="error" />
                              <Chip label="High Risk" size="small" color="warning" />
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>

            {/* Threat Actor Attribution */}
            <Grid item xs={12} lg={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Threat Actor Attribution
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Potential threat actors identified through TTPs and indicators
                  </Typography>
                  <List>
                    {mockCorrelationData.correlation.threat_actor_mentions.map((mention, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <Warning color="error" />
                        </ListItemIcon>
                        <ListItemText
                          primary={mention.actor}
                          secondary={
                            <Box>
                              <Typography variant="body2" color="text.secondary">
                                Referenced in {mention.log_entry}
                              </Typography>
                              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                                <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
                                  Confidence:
                                </Typography>
                                <LinearProgress
                                  variant="determinate"
                                  value={mention.confidence * 100}
                                  color="error"
                                  sx={{ width: 100, height: 4, mr: 1 }}
                                />
                                <Typography variant="caption">
                                  {(mention.confidence * 100).toFixed(0)}%
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

            {/* Recommendations */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Security Recommendations
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    AI-generated actionable recommendations based on correlation analysis
                  </Typography>
                  <TableContainer>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Priority</TableCell>
                          <TableCell>Category</TableCell>
                          <TableCell>Action</TableCell>
                          <TableCell>Details</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {mockCorrelationData.recommendations.map((rec, index) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Chip
                                label={rec.priority}
                                size="small"
                                color={getPriorityColor(rec.priority)}
                              />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                {rec.category}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {rec.action}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" color="text.secondary">
                                {rec.details}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </CardContent>
              </Card>
            </Grid>

            {/* Analysis Timeline */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Analysis Timeline
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                    <Timeline color="primary" />
                    <Typography variant="body2" color="text.secondary">
                      Incident ID: {mockCorrelationData.incident_id}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Analyzed: {new Date(mockCorrelationData.analysis_timestamp).toLocaleString()}
                    </Typography>
                  </Box>
                  
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Log Analysis Completed"
                        secondary="5 security log entries processed and classified"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Threat Intelligence Analysis Completed"
                        secondary="3 threat intelligence reports analyzed for IOCs and TTPs"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Correlation Analysis Completed"
                        secondary="Cross-referenced data sources and identified shared indicators"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <Assessment color="info" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Recommendations Generated"
                        secondary="AI-powered security recommendations based on analysis results"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </motion.div>
      )}

      {!hasResults && !analysisRunning && (
        <Card>
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <Sync sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Analysis Results
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Start a correlation analysis to see cross-referenced results between security logs and threat intelligence.
            </Typography>
            <Button variant="contained" startIcon={<PlayArrow />} onClick={handleStartAnalysis}>
              Start Analysis
            </Button>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default IncidentAnalysis;