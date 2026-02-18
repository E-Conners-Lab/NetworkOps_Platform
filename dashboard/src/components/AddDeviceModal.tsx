/**
 * Add Device Modal
 * Form for onboarding new devices via NetBox with optional auto-provisioning.
 * Supports EVE-NG VM provisioning and Containerlab container provisioning.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { API } from '../config';
import { useAuth } from '../context/AuthContext';

interface Site {
  id: number;
  name: string;
  slug: string;
}

interface Location {
  id: number;
  name: string;
  slug: string;
  site_id: number;
}

interface DeviceType {
  id: number;
  model: string;
  slug: string;
  manufacturer: string;
}

interface DeviceRole {
  id: number;
  name: string;
  slug: string;
}

interface NetmikoType {
  value: string;
  label: string;
}

interface NetboxOptions {
  sites: Site[];
  locations: Location[];
  device_types: DeviceType[];
  roles: DeviceRole[];
  netmiko_types: NetmikoType[];
}

interface ProvisionFeatures {
  automated_provisioning: boolean;
  eve_ng_enabled: boolean;
  containerlab_enabled: boolean;
  eve_ng_available: boolean;
  containerlab_available: boolean;
}

interface EVEImage {
  name: string;
  type: string;
}

interface ContainerlabImage {
  repository: string;
  tag: string;
  size: string;
}

interface ProvisionJob {
  job_id: string;
  correlation_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'rolled_back' | 'cancelled';
  step: string;
  progress_pct: number;
  steps_completed: string[];
  steps_remaining: string[];
  error?: string;
}

type ProvisioningPlatform = 'netbox_only' | 'eve_ng' | 'containerlab';

interface AddDeviceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDeviceAdded: () => void;
}

const AddDeviceModal: React.FC<AddDeviceModalProps> = ({ isOpen, onClose, onDeviceAdded }) => {
  const { getAuthHeaders } = useAuth();

  const [options, setOptions] = useState<NetboxOptions | null>(null);
  const [features, setFeatures] = useState<ProvisionFeatures | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  // Form fields
  const [name, setName] = useState('');
  const [deviceTypeId, setDeviceTypeId] = useState<number | ''>('');
  const [roleId, setRoleId] = useState<number | ''>('');
  const [siteId, setSiteId] = useState<number | ''>('');
  const [locationId, setLocationId] = useState<number | ''>('');
  const [primaryIp, setPrimaryIp] = useState('');
  const [netmikoType, setNetmikoType] = useState('');
  const [containerName, setContainerName] = useState('');

  // Provisioning fields
  const [platform, setPlatform] = useState<ProvisioningPlatform>('netbox_only');
  const [eveImages, setEveImages] = useState<EVEImage[]>([]);
  const [clabImages, setClabImages] = useState<ContainerlabImage[]>([]);
  const [clabKinds, setClabKinds] = useState<string[]>([]);
  const [selectedEveImage, setSelectedEveImage] = useState('');
  const [eveCpu, setEveCpu] = useState(1);
  const [eveRam, setEveRam] = useState(2048);
  const [eveEthernet, setEveEthernet] = useState(4);
  const [selectedClabImage, setSelectedClabImage] = useState('');
  const [selectedClabKind, setSelectedClabKind] = useState('');

  // Provisioning status
  const [provisioningJob, setProvisioningJob] = useState<ProvisionJob | null>(null);
  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  // Check if selected automation type is containerlab
  const isContainerlab = netmikoType.startsWith('containerlab_');

  // Filtered locations based on selected site
  const [filteredLocations, setFilteredLocations] = useState<Location[]>([]);

  const fetchOptions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };

      // Fetch NetBox options
      const resOptions = await fetch(API.netboxOptions, { headers });
      if (!resOptions.ok) {
        const data = await resOptions.json();
        throw new Error(data.error || 'Failed to fetch options');
      }
      const optionsData = await resOptions.json();
      setOptions(optionsData);

      // Fetch provisioning features
      try {
        const resFeatures = await fetch(API.provisionFeatures, { headers });
        if (resFeatures.ok) {
          const featuresData = await resFeatures.json();
          setFeatures(featuresData);
        }
      } catch (e) {
        // Provisioning features not available - that's OK
        setFeatures(null);
      }

    } catch (err: any) {
      setError(err.message || 'Failed to load NetBox options. Is NetBox running?');
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  const fetchEveImages = useCallback(async () => {
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const res = await fetch(API.provisionEveNgImages, { headers });
      if (res.ok) {
        const data = await res.json();
        setEveImages(data.images || []);
      }
    } catch (e) {
      console.error('Failed to fetch EVE-NG images:', e);
    }
  }, [getAuthHeaders]);

  const fetchClabImages = useCallback(async () => {
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const res = await fetch(API.provisionContainerlabImages, { headers });
      if (res.ok) {
        const data = await res.json();
        setClabImages(data.images || []);
        setClabKinds(data.kinds || []);
      }
    } catch (e) {
      console.error('Failed to fetch Containerlab images:', e);
    }
  }, [getAuthHeaders]);

  useEffect(() => {
    if (isOpen) {
      fetchOptions();
      // Reset form
      setName('');
      setDeviceTypeId('');
      setRoleId('');
      setSiteId('');
      setLocationId('');
      setPrimaryIp('');
      setNetmikoType('');
      setContainerName('');
      setPlatform('netbox_only');
      setSelectedEveImage('');
      setEveCpu(1);
      setEveRam(2048);
      setEveEthernet(4);
      setSelectedClabImage('');
      setSelectedClabKind('');
      setProvisioningJob(null);
      setSuccess(null);
      setError(null);
    }
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [isOpen, fetchOptions]);

  // Fetch platform-specific images when platform changes
  useEffect(() => {
    if (platform === 'eve_ng') {
      fetchEveImages();
    } else if (platform === 'containerlab') {
      fetchClabImages();
    }
  }, [platform, fetchEveImages, fetchClabImages]);

  // Filter locations when site changes
  useEffect(() => {
    if (options && siteId !== '') {
      const filtered = options.locations.filter(loc => loc.site_id === siteId);
      setFilteredLocations(filtered);
      // Reset location if not in filtered list
      if (locationId !== '' && !filtered.find(loc => loc.id === locationId)) {
        setLocationId('');
      }
    } else {
      setFilteredLocations(options?.locations || []);
    }
  }, [siteId, options, locationId]);

  const pollJobStatus = useCallback(async (jobId: string) => {
    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const res = await fetch(API.provisionStatus(jobId), { headers });
      if (res.ok) {
        const job: ProvisionJob = await res.json();
        setProvisioningJob(job);

        if (job.status === 'completed') {
          setSuccess(`Device "${name}" provisioned successfully!`);
          onDeviceAdded();
          if (pollingRef.current) {
            clearInterval(pollingRef.current);
            pollingRef.current = null;
          }
          setTimeout(() => onClose(), 2000);
        } else if (job.status === 'failed' || job.status === 'rolled_back' || job.status === 'cancelled') {
          setError(job.error || 'Provisioning failed');
          setSaving(false);
          if (pollingRef.current) {
            clearInterval(pollingRef.current);
            pollingRef.current = null;
          }
        }
      }
    } catch (e) {
      console.error('Failed to poll job status:', e);
    }
  }, [getAuthHeaders, name, onDeviceAdded, onClose]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSaving(true);

    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };

      // First create NetBox device
      const netboxBody: any = {
        name,
        device_type_id: deviceTypeId,
        role_id: roleId,
        site_id: siteId,
      };

      if (locationId !== '') {
        netboxBody.location_id = locationId;
      }
      if (primaryIp) {
        netboxBody.primary_ip = primaryIp.includes('/') ? primaryIp : `${primaryIp}/24`;
      }
      if (netmikoType) {
        netboxBody.netmiko_device_type = netmikoType;
      }
      if (containerName) {
        netboxBody.container_name = containerName;
      }

      const netboxRes = await fetch(API.devices, {
        method: 'POST',
        headers,
        body: JSON.stringify(netboxBody),
      });

      if (!netboxRes.ok) {
        const data = await netboxRes.json();
        throw new Error(data.error || 'Failed to create device in NetBox');
      }

      // If NetBox only, we're done
      if (platform === 'netbox_only') {
        setSuccess(`Device "${name}" created successfully!`);
        onDeviceAdded();
        setTimeout(() => onClose(), 1500);
        return;
      }

      // Otherwise, start provisioning
      let provisionUrl: string;
      const provisionBody: any = {
        name,
        netbox_device_type_id: deviceTypeId,
        netbox_role_id: roleId,
        netbox_site_id: siteId,
      };

      if (platform === 'eve_ng') {
        provisionUrl = API.provisionEveNg;
        provisionBody.template = selectedEveImage;
        provisionBody.cpu = eveCpu;
        provisionBody.ram = eveRam;
        provisionBody.ethernet = eveEthernet;
      } else {
        provisionUrl = API.provisionContainerlab;
        provisionBody.kind = selectedClabKind;
        if (selectedClabImage) {
          provisionBody.image = selectedClabImage;
        }
      }

      const provisionRes = await fetch(provisionUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(provisionBody),
      });

      if (!provisionRes.ok) {
        const data = await provisionRes.json();
        throw new Error(data.error || 'Failed to start provisioning');
      }

      const jobData = await provisionRes.json();
      setProvisioningJob(jobData);

      // Start polling for status
      pollingRef.current = setInterval(() => {
        pollJobStatus(jobData.job_id);
      }, 2000);

    } catch (err: any) {
      setError(err.message);
      setSaving(false);
    }
  };

  const handleCancelProvisioning = async () => {
    if (!provisioningJob) return;

    try {
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      await fetch(API.provisionCancel(provisioningJob.job_id), {
        method: 'POST',
        headers,
      });

      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
      setProvisioningJob(null);
      setSaving(false);
    } catch (e) {
      console.error('Failed to cancel provisioning:', e);
    }
  };

  if (!isOpen) return null;

  const modalStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  };

  const contentStyle: React.CSSProperties = {
    backgroundColor: '#1e1e1e',
    borderRadius: '8px',
    padding: '24px',
    width: '560px',
    maxHeight: '90vh',
    overflow: 'auto',
    border: '1px solid #333',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 12px',
    backgroundColor: '#2d2d2d',
    border: '1px solid #444',
    borderRadius: '4px',
    color: '#e0e0e0',
    fontSize: '14px',
    marginTop: '4px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    marginBottom: '16px',
    color: '#b0b0b0',
    fontSize: '14px',
  };

  const buttonStyle: React.CSSProperties = {
    padding: '10px 20px',
    borderRadius: '4px',
    border: 'none',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 500,
  };

  const sectionStyle: React.CSSProperties = {
    marginTop: '20px',
    paddingTop: '16px',
    borderTop: '1px solid #333',
  };

  const progressBarStyle: React.CSSProperties = {
    width: '100%',
    height: '8px',
    backgroundColor: '#333',
    borderRadius: '4px',
    overflow: 'hidden',
    marginTop: '8px',
  };

  const progressFillStyle = (pct: number): React.CSSProperties => ({
    width: `${pct}%`,
    height: '100%',
    backgroundColor: '#2563eb',
    transition: 'width 0.3s ease',
  });

  // Check if provisioning is enabled for any platform
  const provisioningAvailable = features && features.automated_provisioning &&
    (features.eve_ng_available || features.containerlab_available);

  // Check if form is valid for current platform
  const isFormValid = () => {
    const baseValid = name && deviceTypeId !== '' && roleId !== '' && siteId !== '';
    if (!baseValid) return false;
    if (isContainerlab && !containerName) return false;

    if (platform === 'eve_ng') {
      return !!selectedEveImage;
    } else if (platform === 'containerlab') {
      return !!selectedClabKind;
    }
    return true;
  };

  return (
    <div style={modalStyle} onClick={onClose}>
      <div style={contentStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h2 style={{ margin: 0, color: '#e0e0e0', fontSize: '18px' }}>Add New Device</h2>
          <button
            onClick={onClose}
            style={{ ...buttonStyle, backgroundColor: 'transparent', color: '#888', fontSize: '20px', padding: '4px 8px' }}
          >
            &times;
          </button>
        </div>

        {loading && (
          <div style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
            Loading options...
          </div>
        )}

        {error && !loading && (
          <div style={{ backgroundColor: '#4a1c1c', border: '1px solid #ff6b6b', borderRadius: '4px', padding: '12px', marginBottom: '16px', color: '#ff6b6b' }}>
            {error}
          </div>
        )}

        {success && (
          <div style={{ backgroundColor: '#1c4a1c', border: '1px solid #6bff6b', borderRadius: '4px', padding: '12px', marginBottom: '16px', color: '#6bff6b' }}>
            {success}
          </div>
        )}

        {/* Provisioning Progress */}
        {provisioningJob && provisioningJob.status === 'running' && (
          <div style={{ backgroundColor: '#1c3a4a', border: '1px solid #6bb0ff', borderRadius: '4px', padding: '16px', marginBottom: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#6bb0ff', fontSize: '14px', fontWeight: 500 }}>
                Provisioning in progress...
              </span>
              <button
                onClick={handleCancelProvisioning}
                style={{ ...buttonStyle, backgroundColor: '#4a1c1c', color: '#ff6b6b', padding: '4px 12px', fontSize: '12px' }}
              >
                Cancel
              </button>
            </div>
            <div style={{ color: '#b0b0b0', fontSize: '13px', marginTop: '8px' }}>
              {provisioningJob.step}
            </div>
            <div style={progressBarStyle}>
              <div style={progressFillStyle(provisioningJob.progress_pct)} />
            </div>
            <div style={{ color: '#666', fontSize: '12px', marginTop: '4px' }}>
              {provisioningJob.progress_pct}% complete
            </div>
          </div>
        )}

        {!loading && options && !provisioningJob && (
          <form onSubmit={handleSubmit}>
            {/* Platform Selection */}
            {provisioningAvailable && (
              <div style={{ marginBottom: '20px' }}>
                <div style={{ color: '#b0b0b0', fontSize: '14px', marginBottom: '8px' }}>
                  Provisioning Method
                </div>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={() => setPlatform('netbox_only')}
                    style={{
                      ...buttonStyle,
                      backgroundColor: platform === 'netbox_only' ? '#2563eb' : '#333',
                      color: '#fff',
                      flex: '1 1 auto',
                    }}
                  >
                    NetBox Only
                  </button>
                  {features?.eve_ng_available && (
                    <button
                      type="button"
                      onClick={() => setPlatform('eve_ng')}
                      style={{
                        ...buttonStyle,
                        backgroundColor: platform === 'eve_ng' ? '#2563eb' : '#333',
                        color: '#fff',
                        flex: '1 1 auto',
                      }}
                    >
                      EVE-NG (VM)
                    </button>
                  )}
                  {features?.containerlab_available && (
                    <button
                      type="button"
                      onClick={() => setPlatform('containerlab')}
                      style={{
                        ...buttonStyle,
                        backgroundColor: platform === 'containerlab' ? '#2563eb' : '#333',
                        color: '#fff',
                        flex: '1 1 auto',
                      }}
                    >
                      Containerlab
                    </button>
                  )}
                </div>
                <div style={{ color: '#666', fontSize: '12px', marginTop: '4px' }}>
                  {platform === 'netbox_only' && 'Create NetBox entry only. Manually provision the device.'}
                  {platform === 'eve_ng' && 'Create NetBox entry and auto-provision VM in EVE-NG.'}
                  {platform === 'containerlab' && 'Create NetBox entry and auto-provision container in Containerlab.'}
                </div>
              </div>
            )}

            <label style={labelStyle}>
              Device Name *
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., R5, Switch-R5"
                required
                style={inputStyle}
              />
            </label>

            <label style={labelStyle}>
              Device Type *
              <select
                value={deviceTypeId}
                onChange={(e) => setDeviceTypeId(parseInt(e.target.value) || '')}
                required
                style={inputStyle}
              >
                <option value="">Select device type...</option>
                {options.device_types.map((dt) => (
                  <option key={dt.id} value={dt.id}>
                    {dt.manufacturer} - {dt.model}
                  </option>
                ))}
              </select>
            </label>

            <label style={labelStyle}>
              Role *
              <select
                value={roleId}
                onChange={(e) => setRoleId(parseInt(e.target.value) || '')}
                required
                style={inputStyle}
              >
                <option value="">Select role...</option>
                {options.roles.map((role) => (
                  <option key={role.id} value={role.id}>
                    {role.name}
                  </option>
                ))}
              </select>
            </label>

            <label style={labelStyle}>
              Site *
              <select
                value={siteId}
                onChange={(e) => setSiteId(parseInt(e.target.value) || '')}
                required
                style={inputStyle}
              >
                <option value="">Select site...</option>
                {options.sites.map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
              </select>
            </label>

            <label style={labelStyle}>
              Location (Rack)
              <select
                value={locationId}
                onChange={(e) => setLocationId(parseInt(e.target.value) || '')}
                style={inputStyle}
              >
                <option value="">Select location...</option>
                {filteredLocations.map((loc) => (
                  <option key={loc.id} value={loc.id}>
                    {loc.name}
                  </option>
                ))}
              </select>
            </label>

            <label style={labelStyle}>
              Management IP
              <input
                type="text"
                value={primaryIp}
                onChange={(e) => setPrimaryIp(e.target.value)}
                placeholder={platform !== 'netbox_only' ? 'Auto-allocated from 10.255.255.0/24' : 'e.g., 10.255.255.50/24'}
                style={inputStyle}
                disabled={platform !== 'netbox_only'}
              />
              <small style={{ color: '#666', fontSize: '12px' }}>
                {platform !== 'netbox_only'
                  ? 'IP will be auto-allocated from management prefix'
                  : 'CIDR notation required (e.g., /24)'}
              </small>
            </label>

            <label style={labelStyle}>
              Automation Type
              <select
                value={netmikoType}
                onChange={(e) => setNetmikoType(e.target.value)}
                style={inputStyle}
              >
                <option value="">Select type...</option>
                {options.netmiko_types.map((nt) => (
                  <option key={nt.value} value={nt.value}>
                    {nt.label}
                  </option>
                ))}
              </select>
              <small style={{ color: '#666', fontSize: '12px' }}>Used for SSH automation</small>
            </label>

            {isContainerlab && (
              <label style={labelStyle}>
                Container Name *
                <input
                  type="text"
                  value={containerName}
                  onChange={(e) => setContainerName(e.target.value)}
                  placeholder="e.g., clab-datacenter-R9"
                  required={isContainerlab}
                  style={inputStyle}
                />
                <small style={{ color: '#666', fontSize: '12px' }}>Docker container name in containerlab</small>
              </label>
            )}

            {/* EVE-NG Provisioning Options */}
            {platform === 'eve_ng' && (
              <div style={sectionStyle}>
                <div style={{ color: '#e0e0e0', fontSize: '14px', fontWeight: 500, marginBottom: '16px' }}>
                  EVE-NG Configuration
                </div>

                <label style={labelStyle}>
                  Image/Template *
                  <select
                    value={selectedEveImage}
                    onChange={(e) => setSelectedEveImage(e.target.value)}
                    required
                    style={inputStyle}
                  >
                    <option value="">Select image...</option>
                    {eveImages.map((img) => (
                      <option key={img.name} value={img.name}>
                        {img.name} ({img.type})
                      </option>
                    ))}
                  </select>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                  <label style={labelStyle}>
                    vCPUs
                    <input
                      type="number"
                      value={eveCpu}
                      onChange={(e) => setEveCpu(parseInt(e.target.value) || 1)}
                      min={1}
                      max={8}
                      style={inputStyle}
                    />
                  </label>
                  <label style={labelStyle}>
                    RAM (MB)
                    <input
                      type="number"
                      value={eveRam}
                      onChange={(e) => setEveRam(parseInt(e.target.value) || 2048)}
                      min={512}
                      max={32768}
                      step={512}
                      style={inputStyle}
                    />
                  </label>
                  <label style={labelStyle}>
                    NICs
                    <input
                      type="number"
                      value={eveEthernet}
                      onChange={(e) => setEveEthernet(parseInt(e.target.value) || 4)}
                      min={1}
                      max={16}
                      style={inputStyle}
                    />
                  </label>
                </div>
              </div>
            )}

            {/* Containerlab Provisioning Options */}
            {platform === 'containerlab' && (
              <div style={sectionStyle}>
                <div style={{ color: '#e0e0e0', fontSize: '14px', fontWeight: 500, marginBottom: '16px' }}>
                  Containerlab Configuration
                </div>

                <label style={labelStyle}>
                  Node Kind *
                  <select
                    value={selectedClabKind}
                    onChange={(e) => setSelectedClabKind(e.target.value)}
                    required
                    style={inputStyle}
                  >
                    <option value="">Select kind...</option>
                    {clabKinds.map((kind) => (
                      <option key={kind} value={kind}>
                        {kind}
                      </option>
                    ))}
                  </select>
                  <small style={{ color: '#666', fontSize: '12px' }}>
                    Examples: nokia_srlinux, frr, linux, ceos
                  </small>
                </label>

                <label style={labelStyle}>
                  Container Image (optional)
                  <select
                    value={selectedClabImage}
                    onChange={(e) => setSelectedClabImage(e.target.value)}
                    style={inputStyle}
                  >
                    <option value="">Use default for kind</option>
                    {clabImages.map((img) => (
                      <option key={`${img.repository}:${img.tag}`} value={`${img.repository}:${img.tag}`}>
                        {img.repository}:{img.tag} ({img.size})
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            )}

            <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
              <button
                type="button"
                onClick={onClose}
                style={{ ...buttonStyle, backgroundColor: '#333', color: '#e0e0e0', flex: 1 }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving || !isFormValid()}
                style={{
                  ...buttonStyle,
                  backgroundColor: saving ? '#444' : '#2563eb',
                  color: '#fff',
                  flex: 1,
                  opacity: saving || !isFormValid() ? 0.6 : 1,
                }}
              >
                {saving
                  ? (platform === 'netbox_only' ? 'Creating...' : 'Provisioning...')
                  : (platform === 'netbox_only' ? 'Create Device' : 'Create & Provision')}
              </button>
            </div>
          </form>
        )}

        {!loading && !options && !error && (
          <div style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
            <p>NetBox is not available.</p>
            <p style={{ fontSize: '12px', marginTop: '8px' }}>
              Enable USE_NETBOX=true in .env and ensure NetBox is running.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AddDeviceModal;
