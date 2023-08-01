export function getLogLevel(): string {
    return process.env.LOGS_LEVEL || "debug";
}

export function getOIDCClientId(): string {
    return process.env.OIDC_CLIENT_ID;
}

export function getNodeEnv(): string {
    return process.env.NODE_ENV || "development";
}

export function getLogoutTokenMaxAge(): number {
    return Number(process.env.LOGOUT_TOKEN_MAX_AGE_SECONDS) || 120;
}

export function getTokenValidationClockSkew(): number {
    return Number(process.env.TOKEN_CLOCK_SKEW) || 10;
}

export function getErrorMessage(error: unknown) {
    if (error instanceof Error) return error.message
    return String(error)
}

export function getGlobalLogoutUrl(): string {
    return process.env.GLOBAL_SIGN_OUT_URL || "https://home.integration.account.gov.uk/sign-out";
}