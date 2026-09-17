export interface OAuthFlow {
  tokenUrl: string;
  grantType: string;
  clientId?: string;
  clientSecret?: string;
}

export interface ApkReport {
  appName: string;
  packageName: string;
  analyzedAt: string;
  isFlutter: boolean;
  baseUrls: string[];
  endpoints: string[];
  authConfig: {
    clientIds: string[];
    secrets: string[];
    apiKeys: string[];
    oauthFlows: OAuthFlow[];
  };
  headers: Record<string, string>;
  rawFindings: {
    urls: string[];
    authTokens: string[];
    apiEndpoints: string[];
    customHeaders: string[];
  };
}
