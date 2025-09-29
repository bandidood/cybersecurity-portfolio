import React, { useState, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Tabs,
  Tab,
  TextField,
  Paper,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Collapse,
  Alert,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  CloudUpload,
  PlayArrow,
  ExpandMore,
  ExpandLess,
  Visibility,
  Download,
  FilterList,
  Search,
  Warning,
  CheckCircle,
  Error as ErrorIcon,
  Info,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';

// Mock data for demonstration
const mockAnalysisResults = [
  {
    entry_id: 'LOG-001',
    original_text: 'CRITICAL: Ransomware detected on host SERVER-01 with hash a1b2c3d4e5f6789012345',
    severity: { severity: 'critical', confidence: 0.95 },
    threat_analysis: { threat_level: 'high', total_score: 8 },
    iocs: {
      ip_address: ['192.168.1.100'],
      md5: ['a1b2c3d4e5f6789012345'],
    },
    ml_predictions: {
      log_type: { prediction: 'security_alert', confidence: 0.92 },
      priority: { prediction: 'high', confidence: 0.89 },
    },
  },
  {
    entry_id: 'LOG-002',
    original_text: 'Failed login attempt from IP 203.0.113.42 for user administrator',
    severity: { severity: 'high', confidence: 0.87 },
    threat_analysis: { threat_level: 'medium', total_score: 5 },
    iocs: {
      ip_address: ['203.0.113.42'],
    },
    ml_predictions: {
      log_type: { prediction: 'security_event', confidence: 0.78 },
      priority: { prediction: 'medium', confidence: 0.82 },
    },
  },
  {
    entry_id: 'LOG-003',
    original_text: 'User john successfully logged in from workstation WS-005',
    severity: { severity: 'low', confidence: 0.72 },
    threat_analysis: { threat_level: 'low', total_score: 1 },
    iocs: {},
    ml_predictions: {
      log_type: { prediction: 'normal', confidence: 0.95 },
      priority: { prediction: 'low', confidence: 0.91 },
    },
  },
];

const getSeverityColor = (severity: string): string => {
  switch (severity) {
    case 'critical': return '#ff1744';
    case 'high': return '#ff6b35';
    case 'medium': return '#ffa726';
    case 'low': return '#4caf50';
    default: return '#9ca3af';
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case 'critical': return <ErrorIcon sx={{ fontSize: 18 }} />;
    case 'high': return <Warning sx={{ fontSize: 18 }} />;
    case 'medium': return <Info sx={{ fontSize: 18 }} />;
    case 'low': return <CheckCircle sx={{ fontSize: 18 }} />;
    default: return <Info sx={{ fontSize: 18 }} />;
  }
};

interface FileUploadZoneProps {
  onFilesSelected: (files: File[]) => void;
  processing: boolean;
}

const FileUploadZone: React.FC<FileUploadZoneProps> = ({ onFilesSelected, processing }) => {
  const onDrop = useCallback((acceptedFiles: File[]) => {
    onFilesSelected(acceptedFiles);
  }, [onFilesSelected]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.log', '.txt'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
    },
    disabled: processing,
  });

  return (
    <Paper
      {...getRootProps()}
      sx={{
        p: 4,
        textAlign: 'center',
        border: '2px dashed',
        borderColor: isDragActive ? 'primary.main' : 'rgba(255, 255, 255, 0.3)',
        bgcolor: isDragActive ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255, 255, 255, 0.05)',
        cursor: processing ? 'not-allowed' : 'pointer',
        transition: 'all 0.3s ease',
        '&:hover': {
          borderColor: 'primary.main',
          bgcolor: 'rgba(0, 212, 255, 0.05)',
        },
      }}
    >
      <input {...getInputProps()} />
      <CloudUpload sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
      <Typography variant="h6" gutterBottom>
        {isDragActive ? 'Drop files here...' : 'Upload Security Logs'}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Drag & drop log files here, or click to select
      </Typography>
      <Typography variant="caption" color="text.secondary">
        Supported formats: .log, .txt, .json, .csv (max 100MB)
      </Typography>
      {processing && (
        <Box sx={{ mt: 2 }}>
          <LinearProgress />
          <Typography variant="body2" color="primary.main" sx={{ mt: 1 }}>
            Processing logs...
          </Typography>
        </Box>
      )}
    </Paper>
  );
};

interface LogEntryRowProps {
  result: any;
  expanded: boolean;
  onToggle: () => void;
}

const LogEntryRow: React.FC<LogEntryRowProps> = ({ result, expanded, onToggle }) => {
  return (
    <>
      <TableRow sx={{ '& > *': { borderBottom: 'unset' }, cursor: 'pointer' }} onClick={onToggle}>
        <TableCell>
          <IconButton size="small">
            {expanded ? <ExpandLess /> : <ExpandMore />}
          </IconButton>
        </TableCell>
        <TableCell>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {getSeverityIcon(result.severity.severity)}
            <Chip
              label={result.severity.severity.toUpperCase()}
              size="small"
              sx={{
                bgcolor: `${getSeverityColor(result.severity.severity)}20`,
                color: getSeverityColor(result.severity.severity),
                border: `1px solid ${getSeverityColor(result.severity.severity)}40`,
              }}
            />
          </Box>
        </TableCell>
        <TableCell>
          <Typography variant="body2" noWrap sx={{ maxWidth: 400 }}>
            {result.original_text}
          </Typography>
        </TableCell>
        <TableCell>
          <Chip
            label={result.threat_analysis.threat_level.toUpperCase()}
            size="small"
            color={result.threat_analysis.threat_level === 'high' ? 'error' : result.threat_analysis.threat_level === 'medium' ? 'warning' : 'success'}
          />
        </TableCell>
        <TableCell>
          {Object.keys(result.iocs).length > 0 ? (
            <Chip label={`${Object.values(result.iocs).flat().length} IOCs`} size="small" color="info" />
          ) : (
            <Typography variant="body2" color="text.secondary">None</Typography>
          )}
        </TableCell>
        <TableCell>
          <Typography variant="body2">
            {(result.severity.confidence * 100).toFixed(1)}%
          </Typography>
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
          <Collapse in={expanded} timeout="auto" unmountOnExit>
            <Box sx={{ margin: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    ML Predictions
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'rgba(255, 255, 255, 0.05)' }}>
                    <Typography variant="body2" gutterBottom>
                      <strong>Log Type:</strong> {result.ml_predictions?.log_type.prediction} ({(result.ml_predictions?.log_type.confidence * 100).toFixed(1)}%)
                    </Typography>
                    <Typography variant="body2">
                      <strong>Priority:</strong> {result.ml_predictions?.priority.prediction} ({(result.ml_predictions?.priority.confidence * 100).toFixed(1)}%)
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    IOCs Detected
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'rgba(255, 255, 255, 0.05)' }}>
                    {Object.keys(result.iocs).length > 0 ? (
                      Object.entries(result.iocs).map(([type, values]: [string, any]) => (
                        <Box key={type} sx={{ mb: 1 }}>
                          <Typography variant="body2">
                            <strong>{type.replace('_', ' ').toUpperCase()}:</strong>
                          </Typography>
                          {Array.isArray(values) && values.map((value, idx) => (
                            <Chip key={idx} label={value} size="small" sx={{ ml: 1, mt: 0.5 }} />
                          ))}
                        </Box>
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        No IOCs detected
                      </Typography>
                    )}
                  </Paper>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Full Log Entry
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'rgba(0, 0, 0, 0.3)', fontFamily: 'monospace' }}>
                    <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                      {result.original_text}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
};

const LogAnalysis: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [processing, setProcessing] = useState(false);
  const [results, setResults] = useState(mockAnalysisResults);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [filterDialogOpen, setFilterDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [directInput, setDirectInput] = useState('');

  const handleFilesSelected = (files: File[]) => {
    setSelectedFiles(files);
  };

  const handleProcessFiles = async () => {
    if (selectedFiles.length === 0 && !directInput) {
      return;
    }

    setProcessing(true);
    
    // Simulate processing
    setTimeout(() => {
      setProcessing(false);
      setActiveTab(1); // Switch to results tab
      // In real implementation, this would call the API
    }, 3000);
  };

  const handleDirectAnalysis = () => {
    if (!directInput.trim()) return;
    
    setProcessing(true);
    setTimeout(() => {
      setProcessing(false);
      setActiveTab(1);
    }, 2000);
  };

  const toggleRowExpansion = (entryId: string) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(entryId)) {
      newExpanded.delete(entryId);
    } else {
      newExpanded.add(entryId);
    }
    setExpandedRows(newExpanded);
  };

  const filteredResults = results.filter(result =>
    result.original_text.toLowerCase().includes(searchQuery.toLowerCase()) ||
    result.entry_id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
          Log Analysis
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Upload and analyze security logs using AI-powered threat detection
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}
        >
          <Tab label="Upload & Process" />
          <Tab label="Results" disabled={results.length === 0} />
          <Tab label="Real-time Analysis" />
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
              {/* File Upload */}
              <Grid item xs={12} lg={8}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Upload Log Files
                    </Typography>
                    <FileUploadZone onFilesSelected={handleFilesSelected} processing={processing} />
                    
                    {selectedFiles.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>
                          Selected Files ({selectedFiles.length}):
                        </Typography>
                        {selectedFiles.map((file, index) => (
                          <Chip
                            key={index}
                            label={`${file.name} (${(file.size / 1024).toFixed(1)} KB)`}
                            sx={{ mr: 1, mb: 1 }}
                          />
                        ))}
                      </Box>
                    )}

                    <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
                      <Button
                        variant="contained"
                        startIcon={<PlayArrow />}
                        onClick={handleProcessFiles}
                        disabled={selectedFiles.length === 0 || processing}
                      >
                        {processing ? 'Processing...' : 'Start Analysis'}
                      </Button>
                      <Button variant="outlined">
                        View Sample Data
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              {/* Direct Input */}
              <Grid item xs={12} lg={4}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Direct Log Analysis
                    </Typography>
                    <TextField
                      fullWidth
                      multiline
                      rows={8}
                      placeholder="Paste log entries here for quick analysis..."
                      value={directInput}
                      onChange={(e) => setDirectInput(e.target.value)}
                      sx={{ mb: 2 }}
                    />
                    <Button
                      fullWidth
                      variant="outlined"
                      startIcon={<PlayArrow />}
                      onClick={handleDirectAnalysis}
                      disabled={!directInput.trim() || processing}
                    >
                      Analyze Now
                    </Button>
                  </CardContent>
                </Card>
              </Grid>

              {/* Processing Guide */}
              <Grid item xs={12}>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Processing Steps:
                  </Typography>
                  <Typography variant="body2">
                    1. Upload log files or paste log entries • 2. AI models extract IOCs and classify threats • 
                    3. MITRE ATT&CK techniques are mapped • 4. Results are scored and prioritized
                  </Typography>
                </Alert>
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
            {/* Results Toolbar */}
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Analysis Results ({filteredResults.length})
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    <Button
                      variant="outlined"
                      startIcon={<FilterList />}
                      onClick={() => setFilterDialogOpen(true)}
                    >
                      Filters
                    </Button>
                    <Button variant="outlined" startIcon={<Download />}>
                      Export
                    </Button>
                  </Box>
                </Box>
                
                <TextField
                  fullWidth
                  placeholder="Search logs, IOCs, or entry IDs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: <Search sx={{ mr: 1, color: 'text.secondary' }} />,
                  }}
                />
              </CardContent>
            </Card>

            {/* Results Table */}
            <Card>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell />
                      <TableCell>Severity</TableCell>
                      <TableCell>Log Entry</TableCell>
                      <TableCell>Threat Level</TableCell>
                      <TableCell>IOCs</TableCell>
                      <TableCell>Confidence</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredResults
                      .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                      .map((result) => (
                        <LogEntryRow
                          key={result.entry_id}
                          result={result}
                          expanded={expandedRows.has(result.entry_id)}
                          onToggle={() => toggleRowExpansion(result.entry_id)}
                        />
                      ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <TablePagination
                rowsPerPageOptions={[5, 10, 25]}
                component="div"
                count={filteredResults.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={(_, newPage) => setPage(newPage)}
                onRowsPerPageChange={(e) => {
                  setRowsPerPage(parseInt(e.target.value, 10));
                  setPage(0);
                }}
              />
            </Card>
          </motion.div>
        )}

        {activeTab === 2 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Alert severity="warning">
              <Typography variant="subtitle2" gutterBottom>
                Real-time Analysis Coming Soon
              </Typography>
              <Typography variant="body2">
                Connect directly to SIEM systems, log streams, or APIs for continuous monitoring and analysis.
              </Typography>
            </Alert>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Filter Dialog */}
      <Dialog open={filterDialogOpen} onClose={() => setFilterDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Filter Analysis Results</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Typography variant="subtitle2" gutterBottom>
              Severity Levels
            </Typography>
            {/* Filter controls would go here */}
            <Alert severity="info" sx={{ mt: 2 }}>
              Advanced filtering options will be available in the full version.
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFilterDialogOpen(false)}>Cancel</Button>
          <Button variant="contained">Apply Filters</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default LogAnalysis;