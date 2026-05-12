import { api } from './client'

export const cloudTesterApi = {
  imdsProbe: (target: string | null, providers: string[]) =>
    api.post('/cloud/imds/probe', { target, providers }).then((r) => r.data),

  ssrfGenerate: (callback_url: string, providers: string[]) =>
    api.post('/cloud/ssrf/generate', { callback_url, providers }).then((r) => r.data),

  bucketCheck: (bucket_name: string, provider: string, region = 'us-east-1') =>
    api.post('/cloud/bucket/check', { bucket_name, provider, region }).then((r) => r.data),

  credsScan: (text: string) =>
    api.post('/cloud/creds/scan', { text }).then((r) => r.data),

  credsValidate: (access_key: string, secret_key: string, session_token?: string) =>
    api.post('/cloud/creds/validate', { access_key, secret_key, session_token }).then((r) => r.data),
}
