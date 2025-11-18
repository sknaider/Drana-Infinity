/**
 * DranaScanView Component
 *
 * Main dashboard view for Drana-GTL security scans integrated with GTL Platform.
 * Displays real-time scan status, findings, and compliance information.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Play,
  Pause,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Shield
} from 'lucide-react';
import { ScanCard } from './ScanCard';
import { ScanControls } from './ScanControls';
import { FindingsTable } from './FindingsTable';
import { ComplianceIntegration } from './ComplianceIntegration';
import { ModelAnalytics } from './ModelAnalytics';

// Types
interface DranaScan {
  scanId: string;
  gtlScanJobId: string;
  target: string;
  scanType: string;
  sector: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  modelsUsed: string[];
  startedAt: string;
  completedAt?: string;
  progress: number;
  currentStep: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  confidenceScore?: number;
  complianceFrameworks: string[];
}

interface Finding {
  findingId: string;
  scanId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  threatCategory: string;
  description: string;
  phiExposureRisk: boolean;
  patientSafetyImpact?: string;
  recommendations: string[];
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
}

interface WebSocketMessage {
  type: 'scan_update' | 'scan_complete' | 'finding_detected' | 'progress_update';
  data: any;
}

export const DranaScanView: React.FC = () => {
  const [scans, setScans] = useState<DranaScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<DranaScan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'active' | 'completed'>('active');

  // WebSocket connection for real-time updates
  const { lastMessage, sendMessage, connectionStatus } = useWebSocket('/ws/drana-scans');

  // Load initial scans
  useEffect(() => {
    loadScans();
  }, [filter]);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      handleWebSocketMessage(JSON.parse(lastMessage.data));
    }
  }, [lastMessage]);

  const loadScans = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/v1/drana/scans?filter=${filter}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to load scans: ${response.statusText}`);
      }

      const data = await response.json();
      setScans(data.scans || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scans');
      console.error('Error loading scans:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadFindings = async (scanId: string) => {
    try {
      const response = await fetch(`/api/v1/drana/scans/${scanId}/findings`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to load findings: ${response.statusText}`);
      }

      const data = await response.json();
      setFindings(data.findings || []);
    } catch (err) {
      console.error('Error loading findings:', err);
    }
  };

  const handleWebSocketMessage = (message: WebSocketMessage) => {
    switch (message.type) {
      case 'scan_update':
      case 'progress_update':
        updateScan(message.data);
        break;

      case 'scan_complete':
        updateScan(message.data);
        if (selectedScan?.scanId === message.data.scanId) {
          loadFindings(message.data.scanId);
        }
        break;

      case 'finding_detected':
        if (selectedScan?.scanId === message.data.scanId) {
          setFindings(prev => [...prev, message.data.finding]);
        }
        break;
    }
  };

  const updateScan = (updatedScan: Partial<DranaScan> & { scanId: string }) => {
    setScans(prev => {
      const index = prev.findIndex(s => s.scanId === updatedScan.scanId);
      if (index >= 0) {
        const updated = [...prev];
        updated[index] = { ...updated[index], ...updatedScan };
        return updated;
      } else {
        // New scan
        return [updatedScan as DranaScan, ...prev];
      }
    });

    // Update selected scan if it's the one being updated
    if (selectedScan?.scanId === updatedScan.scanId) {
      setSelectedScan(prev => prev ? { ...prev, ...updatedScan } : null);
    }
  };

  const startScan = async (
    target: string,
    scanType: string,
    sector: string,
    models: string[],
    complianceFrameworks: string[]
  ) => {
    setError(null);

    try {
      const response = await fetch('/api/v1/drana/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          target,
          scanType,
          sector,
          models,
          complianceFrameworks,
          priority: 'normal'
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to start scan: ${response.statusText}`);
      }

      const data = await response.json();
      const newScan: DranaScan = data.scan;

      setScans(prev => [newScan, ...prev]);
      setSelectedScan(newScan);

      // Subscribe to scan updates via WebSocket
      sendMessage(JSON.stringify({
        action: 'subscribe',
        scanId: newScan.scanId
      }));

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
      console.error('Error starting scan:', err);
    }
  };

  const cancelScan = async (scanId: string) => {
    try {
      await fetch(`/api/v1/drana/scans/${scanId}/cancel`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });
    } catch (err) {
      console.error('Error cancelling scan:', err);
    }
  };

  const handleScanSelect = (scan: DranaScan) => {
    setSelectedScan(scan);
    loadFindings(scan.scanId);
  };

  const getStatusIcon = (status: DranaScan['status']) => {
    switch (status) {
      case 'running':
        return <RefreshCw className="w-4 h-4 animate-spin text-blue-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'pending':
        return <Clock className="w-4 h-4 text-gray-500" />;
      default:
        return null;
    }
  };

  const getStats = () => {
    const activeScans = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
    const completedScans = scans.filter(s => s.status === 'completed').length;
    const totalFindings = scans.reduce((sum, s) => sum + s.findingsCount, 0);
    const criticalFindings = scans.reduce((sum, s) => sum + s.criticalCount, 0);

    return { activeScans, completedScans, totalFindings, criticalFindings };
  };

  const stats = getStats();

  if (loading && scans.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
        <span className="ml-2 text-gray-600">Loading scans...</span>
      </div>
    );
  }

  return (
    <div className="drana-scan-view p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Drana-GTL Security Scans</h1>
          <p className="text-gray-600 mt-1">Multi-model AI security scanning powered by Ollama, Claude & DeepSeek</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={connectionStatus === 'connected' ? 'success' : 'destructive'}>
            {connectionStatus === 'connected' ? 'Live' : 'Disconnected'}
          </Badge>
          <Button onClick={loadScans} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
            <RefreshCw className="w-4 h-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.activeScans}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="w-4 h-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.completedScans}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Findings</CardTitle>
            <TrendingUp className="w-4 h-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.totalFindings}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertTriangle className="w-4 h-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.criticalFindings}</div>
          </CardContent>
        </Card>
      </div>

      {/* Scan Controls */}
      <ScanControls onStartScan={startScan} />

      {/* Filter Tabs */}
      <div className="flex gap-2 border-b">
        <button
          className={`px-4 py-2 ${filter === 'all' ? 'border-b-2 border-blue-500 text-blue-600' : 'text-gray-600'}`}
          onClick={() => setFilter('all')}
        >
          All Scans
        </button>
        <button
          className={`px-4 py-2 ${filter === 'active' ? 'border-b-2 border-blue-500 text-blue-600' : 'text-gray-600'}`}
          onClick={() => setFilter('active')}
        >
          Active
        </button>
        <button
          className={`px-4 py-2 ${filter === 'completed' ? 'border-b-2 border-blue-500 text-blue-600' : 'text-gray-600'}`}
          onClick={() => setFilter('completed')}
        >
          Completed
        </button>
      </div>

      {/* Scans List */}
      <div className="grid grid-cols-1 gap-4">
        {scans.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center h-48">
              <Shield className="w-12 h-12 text-gray-400 mb-2" />
              <p className="text-gray-600">No scans found. Start a new scan to get started.</p>
            </CardContent>
          </Card>
        ) : (
          scans.map(scan => (
            <ScanCard
              key={scan.scanId}
              scan={scan}
              selected={selectedScan?.scanId === scan.scanId}
              onSelect={() => handleScanSelect(scan)}
              onCancel={() => cancelScan(scan.scanId)}
              getStatusIcon={getStatusIcon}
            />
          ))
        )}
      </div>

      {/* Selected Scan Details */}
      {selectedScan && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Scan Details: {selectedScan.target}</CardTitle>
              <CardDescription>
                Scan ID: {selectedScan.scanId} | GTL Job ID: {selectedScan.gtlScanJobId}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-sm text-gray-600">Status</div>
                  <div className="flex items-center gap-2 mt-1">
                    {getStatusIcon(selectedScan.status)}
                    <span className="capitalize">{selectedScan.status}</span>
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Progress</div>
                  <div className="mt-1">{selectedScan.progress}%</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Models</div>
                  <div className="flex gap-1 mt-1">
                    {selectedScan.modelsUsed.map(model => (
                      <Badge key={model} variant="outline">{model}</Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Confidence</div>
                  <div className="mt-1">{selectedScan.confidenceScore ? (selectedScan.confidenceScore * 100).toFixed(1) + '%' : 'N/A'}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Findings Table */}
          <FindingsTable findings={findings} />

          {/* Model Analytics */}
          <ModelAnalytics scanId={selectedScan.scanId} />

          {/* Compliance Integration */}
          <ComplianceIntegration
            scan={selectedScan}
            findings={findings}
          />
        </div>
      )}
    </div>
  );
};

export default DranaScanView;
