import React, { useState } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Tabs,
  Tab,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Avatar,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  Divider,
  Alert,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
} from '@mui/material';
import {
  Add,
  ExpandMore,
  Security,
  Public,
  Flag,
  Assessment,
  Timeline,
  Person,
  BugReport,
  Link as LinkIcon,
  CloudUpload,
  PlayArrow,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';

// Mock data for threat intelligence
const mockThreatActors = [
  {
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'Office Monkeys'],
    country: 'Russia',
    motivation: 'Espionage',
    confidence: 0.9,
    techniques: ['T1059', 'T1071', 'T1566'],
    recentActivity: '2 days ago',
    avatar: 'A29',
  },
  {
    name: 'APT28',
    aliases: ['Fancy Bear', 'Pawn Storm'],
    country: 'Russia',
    motivation: 'Espionage',
    confidence: 0.85,
    techniques: ['T1566', 'T1053', 'T1105'],
    recentActivity: '1 week ago',
    avatar: 'A28',
  },
  {
    name: 'Lazarus',
    aliases: ['HIDDEN COBRA'],
    country: 'North Korea',
    motivation: 'Financial/Espionage',
    confidence: 0.88,
    techniques: ['T1055', 'T1003', 'T1071'],
    recentActivity: '3 days ago',
    avatar: 'LAZ',
  },
];

const mockMitreTechniques = [
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands',
    detectionCount: 15,
    severity: 'high',
  },
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send victims emails containing malicious attachments',
    detectionCount: 23,
    severity: 'critical',
  },
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes in order to evade detection',
    detectionCount: 8,
    severity: 'medium',
  },
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols',
    detectionCount: 12,
    severity: 'high',
  },
];

const mockThreatReports = [
  {
    id: 'CTI-001',
    title: 'APT29 Campaign Targeting Healthcare Organizations',
    source: 'Internal Analysis',
    confidence: 0.92,
    timestamp: '2024-01-15T10:30:00Z',
    iocCount: 47,
    ttps: ['T1566', 'T1059', 'T1071'],
    summary: 'Advanced persistent threat group APT29 has been observed targeting healthcare organizations using COVID-themed phishing emails.',
    attribution: 'APT29',
  },
  {
    id: 'CTI-002',
    title: 'Ransomware Campaign Analysis',
    source: 'External Feed',
    confidence: 0.87,
    timestamp: '2024-01-14T15:45:00Z',
    iocCount: 23,
    ttps: ['T1486', 'T1053', 'T1055'],
    summary: 'New ransomware variant observed with enhanced encryption capabilities and lateral movement techniques.',
    attribution: null,
  },
  {
    id: 'CTI-003',
    title: 'Banking Trojan Infrastructure Analysis',
    source: 'Threat Feed',
    confidence: 0.79,
    timestamp: '2024-01-13T09:15:00Z',
    iocCount: 156,
    ttps: ['T1003', 'T1071', 'T1027'],
    summary: 'Analysis of banking trojan infrastructure reveals connections to known cybercriminal groups.',
    attribution: 'FIN7',
  },
];

const getConfidenceColor = (confidence: number) => {
  if (confidence >= 0.8) return 'success';
  if (confidence >= 0.6) return 'warning';
  return 'error';
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return '#ff1744';
    case 'high': return '#ff6b35';
    case 'medium': return '#ffa726';
    case 'low': return '#4caf50';
    default: return '#9ca3af';
  }
};

const ThreatActorCard: React.FC<{ actor: any }> = ({ actor }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Avatar
          sx={{
            bgcolor: 'primary.main',
            width: 48,
            height: 48,
            mr: 2,
            fontSize: '0.75rem',
            fontWeight: 600,
          }}
        >
          {actor.avatar}
        </Avatar>
        <Box sx={{ flex: 1 }}>
          <Typography variant="h6" gutterBottom>
            {actor.name}
          </Typography>
          <Chip
            size="small"
            label={actor.country}
            icon={<Flag />}
            sx={{ bgcolor: 'rgba(255, 255, 255, 0.1)' }}
          />
        </Box>
      </Box>

      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {actor.motivation}
      </Typography>

      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary">
          Confidence Level
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
          <LinearProgress
            variant="determinate"
            value={actor.confidence * 100}
            color={getConfidenceColor(actor.confidence)}
            sx={{ flex: 1, mr: 1, height: 6, borderRadius: 3 }}
          />
          <Typography variant="caption">
            {(actor.confidence * 100).toFixed(0)}%
          </Typography>
        </Box>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" gutterBottom display="block">
          Techniques ({actor.techniques.length})
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {actor.techniques.map((technique) => (
            <Chip
              key={technique}
              label={technique}
              size="small"
              variant="outlined"
              sx={{ fontSize: '0.7rem' }}
            />
          ))}
        </Box>
      </Box>

      <Typography variant="caption" color="text.secondary">
        Last Activity: {actor.recentActivity}
      </Typography>
    </CardContent>
  </Card>
);

const MitreTechniqueCard: React.FC<{ technique: any }> = ({ technique }) => (
  <Card>
    <CardContent>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
        <Box>
          <Typography variant="h6" gutterBottom>
            {technique.id}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {technique.name}
          </Typography>
        </Box>
        <Badge badgeContent={technique.detectionCount} color="error">
          <Security />
        </Badge>
      </Box>

      <Chip
        label={technique.tactic}
        size="small"
        sx={{
          bgcolor: `${getSeverityColor(technique.severity)}20`,
          color: getSeverityColor(technique.severity),
          mb: 2,
        }}
      />

      <Typography variant="body2" sx={{ mb: 2 }}>
        {technique.description}
      </Typography>

      <Typography variant="caption" color="primary.main">
        View MITRE Details →
      </Typography>
    </CardContent>
  </Card>
);

const ThreatIntelligence: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [reportInput, setReportInput] = useState('');
  const [processing, setProcessing] = useState(false);

  const handleAnalyzeReport = () => {
    if (!reportInput.trim()) return;

    setProcessing(true);
    setTimeout(() => {
      setProcessing(false);
      // Simulate analysis completion
    }, 3000);
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
          Threat Intelligence
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Analyze threat reports, map MITRE ATT&CK techniques, and track threat actors
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}
        >
          <Tab label="Report Analysis" />
          <Tab label="Threat Actors" />
          <Tab label="MITRE ATT&CK" />
          <Tab label="IOC Intelligence" />
        </Tabs>
      </Paper>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Grid container spacing={3}>
              {/* Report Input */}
              <Grid item xs={12} lg={8}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Threat Report Analysis
                    </Typography>
                    <TextField
                      fullWidth
                      multiline
                      rows={12}
                      placeholder="Paste threat intelligence report here for analysis..."
                      value={reportInput}
                      onChange={(e) => setReportInput(e.target.value)}
                      sx={{ mb: 2 }}
                    />
                    {processing && (
                      <Box sx={{ mb: 2 }}>
                        <LinearProgress />
                        <Typography variant="body2" color="primary.main" sx={{ mt: 1 }}>
                          Analyzing report for IOCs, TTPs, and threat actor attribution...
                        </Typography>
                      </Box>
                    )}
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <Button
                        variant="contained"
                        startIcon={<PlayArrow />}
                        onClick={handleAnalyzeReport}
                        disabled={!reportInput.trim() || processing}
                      >
                        {processing ? 'Analyzing...' : 'Analyze Report'}
                      </Button>
                      <Button
                        variant="outlined"
                        startIcon={<CloudUpload />}
                        disabled={processing}
                      >
                        Upload File
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              {/* Analysis Settings */}
              <Grid item xs={12} lg={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Analysis Configuration
                    </Typography>
                    <List>
                      <ListItem>
                        <ListItemText
                          primary="IOC Extraction"
                          secondary="Extract indicators of compromise"
                        />
                      </ListItem>
                      <Divider />
                      <ListItem>
                        <ListItemText
                          primary="TTP Mapping"
                          secondary="Map to MITRE ATT&CK framework"
                        />
                      </ListItem>
                      <Divider />
                      <ListItem>
                        <ListItemText
                          primary="Attribution"
                          secondary="Identify potential threat actors"
                        />
                      </ListItem>
                      <Divider />
                      <ListItem>
                        <ListItemText
                          primary="Confidence Scoring"
                          secondary="AI-powered confidence assessment"
                        />
                      </ListItem>
                    </List>
                  </CardContent>
                </Card>
              </Grid>

              {/* Recent Reports */}
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Recent Analysis Results
                    </Typography>
                    <TableContainer>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell>Report</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Attribution</TableCell>
                            <TableCell>IOCs</TableCell>
                            <TableCell>Confidence</TableCell>
                            <TableCell>Date</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {mockThreatReports.map((report) => (
                            <TableRow key={report.id}>
                              <TableCell>
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                  {report.title}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {report.summary}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip label={report.source} size="small" />
                              </TableCell>
                              <TableCell>
                                {report.attribution ? (
                                  <Chip
                                    label={report.attribution}
                                    size="small"
                                    color="error"
                                    icon={<Person />}
                                  />
                                ) : (
                                  <Typography variant="body2" color="text.secondary">
                                    Unknown
                                  </Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={`${report.iocCount} IOCs`}
                                  size="small"
                                  color="info"
                                />
                              </TableCell>
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  <LinearProgress
                                    variant="determinate"
                                    value={report.confidence * 100}
                                    color={getConfidenceColor(report.confidence)}
                                    sx={{ width: 60, height: 4 }}
                                  />
                                  <Typography variant="caption">
                                    {(report.confidence * 100).toFixed(0)}%
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Typography variant="caption">
                                  {new Date(report.timestamp).toLocaleDateString()}
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
            </Grid>
          </motion.div>
        )}

        {activeTab === 1 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Grid container spacing={3}>
              {mockThreatActors.map((actor) => (
                <Grid item xs={12} md={6} lg={4} key={actor.name}>
                  <ThreatActorCard actor={actor} />
                </Grid>
              ))}
              
              {/* Add New Threat Actor */}
              <Grid item xs={12} md={6} lg={4}>
                <Card
                  sx={{
                    height: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '2px dashed rgba(255, 255, 255, 0.3)',
                    cursor: 'pointer',
                    '&:hover': {
                      border: '2px dashed',
                      borderColor: 'primary.main',
                      bgcolor: 'rgba(0, 212, 255, 0.05)',
                    },
                  }}
                >
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Add sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                    <Typography variant="h6" color="text.secondary">
                      Add Threat Actor
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </motion.div>
        )}

        {activeTab === 2 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Grid container spacing={3}>
              {/* MITRE ATT&CK Overview */}
              <Grid item xs={12}>
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    MITRE ATT&CK Framework Integration
                  </Typography>
                  <Typography variant="body2">
                    Automatically map detected techniques to the MITRE ATT&CK framework for comprehensive threat analysis.
                  </Typography>
                </Alert>
              </Grid>

              {mockMitreTechniques.map((technique) => (
                <Grid item xs={12} md={6} lg={3} key={technique.id}>
                  <MitreTechniqueCard technique={technique} />
                </Grid>
              ))}

              {/* Technique Details */}
              <Grid item xs={12}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Technique Detection Timeline
                    </Typography>
                    <Box sx={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Typography color="text.secondary">
                        Timeline visualization will be displayed here
                      </Typography>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </motion.div>
        )}

        {activeTab === 3 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Alert severity="warning">
                  <Typography variant="subtitle2" gutterBottom>
                    IOC Intelligence Database
                  </Typography>
                  <Typography variant="body2">
                    Enhanced IOC intelligence features including reputation scoring, historical analysis, and threat feed integration coming soon.
                  </Typography>
                </Alert>
              </Grid>

              {/* IOC Statistics */}
              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <BugReport sx={{ fontSize: 32, color: 'error.main', mr: 2 }} />
                      <Box>
                        <Typography variant="h4" color="error.main">
                          1,247
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Malicious IOCs
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <LinkIcon sx={{ fontSize: 32, color: 'warning.main', mr: 2 }} />
                      <Box>
                        <Typography variant="h4" color="warning.main">
                          856
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Suspicious Domains
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={4}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <Public sx={{ fontSize: 32, color: 'info.main', mr: 2 }} />
                      <Box>
                        <Typography variant="h4" color="info.main">
                          432
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          C2 Infrastructure
                        </Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </motion.div>
        )}
      </AnimatePresence>
    </Box>
  );
};

export default ThreatIntelligence;