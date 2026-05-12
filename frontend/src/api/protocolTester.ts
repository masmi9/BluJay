import { api } from './client'

export const protocolTesterApi = {
  tlsScan: (host: string, port = 443) =>
    api.post('/protocol/tls/scan', { host, port }).then((r) => r.data),

  subdomainEnum: (domain: string, include_crtsh = true, wordlist: string[] = []) =>
    api.post('/protocol/subdomain/enum', { domain, include_crtsh, wordlist }).then((r) => r.data),

  ldapEnum: (host: string, port = 389, bind_dn = '', bind_password = '', base_dn = '') =>
    api.post('/protocol/ldap/enum', { host, port, bind_dn, bind_password, base_dn }).then((r) => r.data),

  grpcReflect: (host: string, port = 50051, use_tls = false) =>
    api.post('/protocol/grpc/reflect', { host, port, use_tls }).then((r) => r.data),

  grpcSend: (host: string, port: number, service: string, method: string, payload: object, use_tls = false) =>
    api.post('/protocol/grpc/send', { host, port, service, method, payload, use_tls }).then((r) => r.data),

  grpcFuzz: (host: string, port: number, service: string, method: string, field_map: object, use_tls = false) =>
    api.post('/protocol/grpc/fuzz', { host, port, service, method, field_map, use_tls }).then((r) => r.data),
}
