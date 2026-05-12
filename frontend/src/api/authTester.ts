import { api } from './client'

export const authTesterApi = {
  jwtDecode: (token: string) =>
    api.post('/auth/jwt/decode', { token }).then((r) => r.data),

  jwtForge: (token: string, attack: string, secret = '', kid_payload = "' OR '1'='1") =>
    api.post('/auth/jwt/forge', { token, attack, secret, kid_payload }).then((r) => r.data),

  jwtVerify: (token: string, secret: string, algorithm = 'HS256') =>
    api.post('/auth/jwt/verify', { token, secret, algorithm }).then((r) => r.data),

  oauthAudit: (authorization_url: string) =>
    api.post('/auth/oauth/audit', { authorization_url }).then((r) => r.data),

  sessionAnalyze: (set_cookie_headers: string[]) =>
    api.post('/auth/session/analyze', { set_cookie_headers }).then((r) => r.data),

  samlDecode: (saml_message: string, is_response = false) =>
    api.post('/auth/saml/decode', { saml_message, is_response }).then((r) => r.data),
}
