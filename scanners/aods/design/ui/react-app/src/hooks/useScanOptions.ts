import { useReducer, useCallback, useEffect, useRef } from 'react';

const STORAGE_KEY = 'aodsScanOptions';

export interface ScanOptions {
  scanProfile: string;
  scanMode: string;
  outputFormats: string[];
  staticOnly: boolean;
  enableFilter: boolean;
  profile: string;
  fridaMode: string;
  resourceConstrained: boolean;
  maxWorkers: string;
  timeoutsProfile: string;
  pluginsIncludeCSV: string;
  pluginsExcludeCSV: string;
  ciMode: boolean;
  failOnCritical: boolean;
  failOnHigh: boolean;
  frameworks: string[];
  compliance: string;
  mlConfidence: string;
  mlModelsPath: string;
  dedupStrategy: string;
  dedupThreshold: string;
  progressiveAnalysis: boolean;
  sampleRate: string;
  agentEnabled: boolean;
  agentSteps: string[];
}

const DEFAULT_OPTIONS: ScanOptions = {
  scanProfile: 'standard',
  scanMode: 'safe',
  outputFormats: ['json', 'html'],
  staticOnly: false,
  enableFilter: false,
  profile: 'dev',
  fridaMode: '',
  resourceConstrained: false,
  maxWorkers: '',
  timeoutsProfile: '',
  pluginsIncludeCSV: '',
  pluginsExcludeCSV: '',
  ciMode: false,
  failOnCritical: false,
  failOnHigh: false,
  frameworks: [],
  compliance: '',
  mlConfidence: '',
  mlModelsPath: '',
  dedupStrategy: '',
  dedupThreshold: '',
  progressiveAnalysis: false,
  sampleRate: '',
  agentEnabled: false,
  agentSteps: [],
};

type UpdateAction = {
  type: 'update';
  key: keyof ScanOptions;
  value: ScanOptions[keyof ScanOptions];
};

type ResetAction = {
  type: 'reset';
};

type BulkUpdateAction = {
  type: 'bulk';
  patch: Partial<ScanOptions>;
};

type ScanOptionsAction = UpdateAction | ResetAction | BulkUpdateAction;

function reducer(state: ScanOptions, action: ScanOptionsAction): ScanOptions {
  switch (action.type) {
    case 'update':
      return { ...state, [action.key]: action.value };
    case 'bulk':
      return { ...state, ...action.patch };
    case 'reset':
      return { ...DEFAULT_OPTIONS };
    default:
      return state;
  }
}

/** Read Config page scan defaults (profile + formats) if set. */
function readConfigDefaults(): Partial<ScanOptions> {
  try {
    const raw = localStorage.getItem('aodsScanDefaults');
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return {};
    const patch: Partial<ScanOptions> = {};
    if (typeof parsed.profile === 'string' && parsed.profile) patch.scanProfile = parsed.profile;
    if (Array.isArray(parsed.formats) && parsed.formats.length > 0) patch.outputFormats = parsed.formats;
    return patch;
  } catch { return {}; }
}

function loadFromStorage(): ScanOptions {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      // No user-specific options - apply Config page defaults
      return { ...DEFAULT_OPTIONS, ...readConfigDefaults() };
    }
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return { ...DEFAULT_OPTIONS, ...readConfigDefaults() };
    // Merge with defaults so new fields always have a value
    return { ...DEFAULT_OPTIONS, ...parsed };
  } catch {
    // Fall back to individual legacy keys for migration
    return migrateLegacyKeys();
  }
}

/** One-time migration from individual useLocalStorage keys to the consolidated object. */
function migrateLegacyKeys(): ScanOptions {
  const opts = { ...DEFAULT_OPTIONS };
  try {
    const str = (key: string, def: string): string => {
      const v = localStorage.getItem(key);
      if (v === null) return def;
      try { return JSON.parse(v) as string; } catch { return v; }
    };
    const bool = (key: string, def: boolean): boolean => {
      const v = localStorage.getItem(key);
      if (v === null) return def;
      try { return JSON.parse(v) as boolean; } catch { return def; }
    };
    const arr = (key: string, def: string[]): string[] => {
      const v = localStorage.getItem(key);
      if (v === null) return def;
      try { return JSON.parse(v) as string[]; } catch { return def; }
    };

    opts.scanProfile = str('aodsNewScan_scanProfile', DEFAULT_OPTIONS.scanProfile);
    opts.scanMode = str('aodsNewScan_scanMode', DEFAULT_OPTIONS.scanMode);
    opts.outputFormats = arr('aodsNewScan_formats', DEFAULT_OPTIONS.outputFormats);
    opts.staticOnly = bool('aodsNewScan_staticOnly', DEFAULT_OPTIONS.staticOnly);
    opts.enableFilter = bool('aodsNewScan_filter', DEFAULT_OPTIONS.enableFilter);
    opts.profile = str('aodsNewScan_profile', DEFAULT_OPTIONS.profile);
    opts.fridaMode = str('aodsNewScan_fridaMode', DEFAULT_OPTIONS.fridaMode);
    opts.resourceConstrained = bool('aodsNewScan_resourceConstrained', DEFAULT_OPTIONS.resourceConstrained);
    opts.maxWorkers = str('aodsNewScan_maxWorkers', DEFAULT_OPTIONS.maxWorkers);
    opts.timeoutsProfile = str('aodsNewScan_timeoutsProfile', DEFAULT_OPTIONS.timeoutsProfile);
    opts.pluginsIncludeCSV = str('aodsNewScan_pluginsInclude', DEFAULT_OPTIONS.pluginsIncludeCSV);
    opts.pluginsExcludeCSV = str('aodsNewScan_pluginsExclude', DEFAULT_OPTIONS.pluginsExcludeCSV);
    opts.ciMode = bool('aodsNewScan_ciMode', DEFAULT_OPTIONS.ciMode);
    opts.failOnCritical = bool('aodsNewScan_failCrit', DEFAULT_OPTIONS.failOnCritical);
    opts.failOnHigh = bool('aodsNewScan_failHigh', DEFAULT_OPTIONS.failOnHigh);
    opts.frameworks = arr('aodsNewScan_frameworks', DEFAULT_OPTIONS.frameworks);
    opts.compliance = str('aodsNewScan_compliance', DEFAULT_OPTIONS.compliance);
    opts.mlConfidence = str('aodsNewScan_mlConf', DEFAULT_OPTIONS.mlConfidence);
    opts.mlModelsPath = str('aodsNewScan_mlModels', DEFAULT_OPTIONS.mlModelsPath);
    opts.dedupStrategy = str('aodsNewScan_dedupStrategy', DEFAULT_OPTIONS.dedupStrategy);
    opts.dedupThreshold = str('aodsNewScan_dedupThreshold', DEFAULT_OPTIONS.dedupThreshold);
    opts.progressiveAnalysis = bool('aodsNewScan_progressive', DEFAULT_OPTIONS.progressiveAnalysis);
    opts.sampleRate = str('aodsNewScan_sampleRate', DEFAULT_OPTIONS.sampleRate);
  } catch { /* keep defaults */ }
  return opts;
}

export type UpdateOptionFn = <K extends keyof ScanOptions>(key: K, value: ScanOptions[K]) => void;
export type BulkUpdateFn = (patch: Partial<ScanOptions>) => void;

export interface UseScanOptionsReturn {
  options: ScanOptions;
  updateOption: UpdateOptionFn;
  bulkUpdate: BulkUpdateFn;
  resetOptions: () => void;
}

/**
 * Consolidates all scan option state into a single useReducer,
 * persisted to localStorage under the `aodsScanOptions` key.
 * Migrates from legacy per-field keys on first load.
 */
export function useScanOptions(): UseScanOptionsReturn {
  const [options, dispatch] = useReducer(reducer, undefined, loadFromStorage);
  const isInitialMount = useRef(true);

  // Persist to localStorage on every state change (skip initial mount to avoid redundant write)
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
      // Write on initial mount too, to consolidate migrated keys
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(options)); } catch {}
      return;
    }
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(options));
    } catch { /* quota exceeded - keep in-memory value */ }
  }, [options]);

  // Sync across tabs via storage event
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      try {
        if (e.newValue === null) {
          dispatch({ type: 'reset' });
        } else {
          const parsed = JSON.parse(e.newValue);
          if (typeof parsed === 'object' && parsed !== null) {
            dispatch({ type: 'bulk', patch: parsed });
          }
        }
      } catch { /* ignore malformed */ }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const updateOption = useCallback(<K extends keyof ScanOptions>(key: K, value: ScanOptions[K]) => {
    dispatch({ type: 'update', key, value });
  }, []);

  const bulkUpdate = useCallback((patch: Partial<ScanOptions>) => {
    dispatch({ type: 'bulk', patch });
  }, []);

  const resetOptions = useCallback(() => {
    dispatch({ type: 'reset' });
  }, []);

  return { options, updateOption, bulkUpdate, resetOptions };
}
