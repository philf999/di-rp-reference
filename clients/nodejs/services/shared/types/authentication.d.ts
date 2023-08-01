type AuthMiddlewareConfiguration = {
  clientId: string;
  clientSecret?: string;
  privateKey: string;
  clientMetadata?: Partial<ClientMetadata>;
  authorizeRedirectUri?: string;
  postLogoutRedirectUri?: string;
  callbackRedirectUri?: string;
  identityVerificationPublicKey?: string;
} & (
  | {
      issuerMetadata: IssuerMetadata;
    }
  | {
      discoveryEndpoint: string;
      issuerMetadata?: Partial<IssuerMetadata>;
    }
);

type IdentityCheckCredential = {
  credentialSubject: {
    name: Array<any>;
    birthDate: Array<any>;
  };
};

type GovUkOneLoginUserInfo = {
  ["https://vocab.account.gov.uk/v1/coreIdentityJWT"]?: string;
};

type LogoutToken = {
  iss: string;
  sub?: string;
  aud: string;
  iat: number;
  jti: string;
  sid?: string;
  events?: any;
};

