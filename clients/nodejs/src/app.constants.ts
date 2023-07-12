export const PATH_DATA: {
  [key: string]: { url: string; };
} = {
  
  AUTH_CALLBACK: { url: "/auth/callback" },
  SESSION_EXPIRED: { url: "/session-expired" },
  USER_SIGNED_OUT: { url: "/signed-out" },
  SIGN_OUT: { url: "/sign-out" },
  START: { url: "/" },
  BACK_CHANNEL_LOGOUT: { url: "/back-channel-logout" }
};

export const VECTORS_OF_TRUST = {
  AUTH_MEDIUM: "Cl.Cm",
  AUTH_LOW: "Cl",
  AUTH_MEDIUM_IDENTITY_MEDIUM: "Cl.Cm.P2"
};

export const HTTP_STATUS_CODES = {
  NOT_FOUND: 404,
  INTERNAL_SERVER_ERROR: 500,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  OK: 200,
  NO_CONTENT: 204,
  REDIRECT: 303,
};

export enum LOCALE {
  EN = "en",
  CY = "cy",
}

// Scopes
export const SCOPES = [
    "openid", // Always included
    "email", // Return the user's email address (NB: this is the username rather than their preferred communication email address) 
    "phone", // Return the user's telephone number
    "offline_access" // Return a refresh token so the access token can be refreshed before it expires
];