import { Request, Response, Router, urlencoded } from "express";
import { jwtVerify, decodeJwt, KeyLike, createRemoteJWKSet } from "jose";
import { Client, generators, TokenSet, AuthorizationParameters, } from "openid-client";
import asyncHandler from "../async-handler";
import { Claims, createClient, createIssuer, hash, readPrivateKey, readPublicKey } from "../govuk-one-login";
import { PATH_DATA, VECTORS_OF_TRUST, LOCALE, SCOPES, HTTP_STATUS_CODES } from "../app.constants";
import { getLogoutTokenMaxAge, getTokenValidationClockSkew, getErrorMessage} from "../config";

// Requested claims
const CLAIMS = {
  userinfo: {
    // Core identity
    [Claims.CoreIdentity]: { essential: true },
    // Address
    //[Claims.Address]: { essential: true },
  },
};

// Issuer that is must have issued identity claims.
const ISSUER = "https://identity.integration.account.gov.uk/";
const STATE_COOKIE_NAME = "state";
const NONCE_COOKIE_NAME = "nonce";
const ID_TOKEN_COOKIE_NAME = "id-token";
const BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

function getRedirectUri(req: Request) {
  const protocol = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers.host;
  return `${protocol}://${host}/oauth/callback`;
}

async function getResult(
  res: Response,
  ivPublicKey: KeyLike,
  client: Client,
  tokenSet: TokenSet
) {
  if (!tokenSet.access_token) {
    throw new Error("No access token received");
  }
  else {
    console.log(tokenSet.access_token);
  }

  if (!tokenSet.id_token) {
    throw new Error("No id token received");
  }
  else {
    console.log(tokenSet.id_token);
  }

  const accessToken = JSON.stringify(decodeJwt(tokenSet.access_token), null, 2);
  const idToken = tokenSet.id_token
    ? JSON.stringify(decodeJwt(tokenSet.id_token), null, 2)
    : undefined;

  res.cookie(ID_TOKEN_COOKIE_NAME, tokenSet.id_token, {
    httpOnly: true,
  });

  const refreshToken = tokenSet.refresh_token
    ? JSON.stringify(decodeJwt(tokenSet.refresh_token), null, 2)
    : undefined;

  // Use the access token to authenticate the call to userinfo
  // Note: This is an HTTP GET to https://oidc.integration.account.gov.uk/userinfo
  // with the "Authorization: Bearer ${accessToken}` header
  const userinfo = await client.userinfo<GovUkOneLoginUserInfo>(
    tokenSet.access_token
  );

  // If the core identity claim is not present GOV.UK One Login
  // was not able to prove your user’s identity or the claim
  // wasn't requested.
  let coreIdentity: string | undefined;
  if (userinfo.hasOwnProperty(Claims.CoreIdentity)) {

    // Read the resulting core identity claim
    // See: https://auth-tech-docs.london.cloudapps.digital/integrate-with-integration-environment/process-identity-information/#process-your-user-s-identity-information
    const coreIdentityJWT = userinfo[Claims.CoreIdentity];

    // Check the validity of the claim using the public key
    const { payload } = await jwtVerify(coreIdentityJWT!, ivPublicKey, {
      issuer: ISSUER,
    });

    // Check the Vector of Trust (vot) to ensure the expected level of confidence was achieved.
    if (payload.vot !== "P2") {
      throw new Error("Expected level of confidence was not achieved.");
    }

    coreIdentity = JSON.stringify(payload, null, 2);
  }

  return {
    accessToken,
    refreshToken,
    idToken,
    userinfo: JSON.stringify(userinfo, null, 2),
    coreIdentity,
  };
}

export async function auth(configuration: AuthMiddlewareConfiguration) {
  // Load private key is required for signing token exchange
  const jwks = [readPrivateKey(configuration.privateKey).export({
    format: "jwk",
  })]

  // Load the public key required to verify the core identity claim
  const ivPublicKey = readPublicKey(
    configuration.identityVerificationPublicKey!
  );

  // Configuration for the authority that authenticates users and issues the tokens.
  const issuer: any = await createIssuer(configuration);

  // The client that requests the tokens.
  const client = createClient(configuration, issuer, jwks);

  const router = Router();

  router.get("/oauth/login", (req: Request, res: Response) => {

    // Calculate the redirect URL the should be returned to after completing the OAuth flow
    const redirectUri =
    configuration.authorizeRedirectUri ||
    getRedirectUri(req);

    // Generate values that protect the flow from replay attacks.
    const nonce = generators.nonce();
    const state = generators.state();
    
    // Store the nonce and state in a session cookie so it can be checked in callback
    res.cookie(NONCE_COOKIE_NAME, nonce, {
      httpOnly: true,
    });
    res.cookie(STATE_COOKIE_NAME, state, {
      httpOnly: true,
    });

    const authorizationParameters: AuthorizationParameters = {
      redirect_uri: redirectUri,
      response_type: "code",
      scope: SCOPES.join(" "),
      state: hash(state),
      nonce: hash(nonce),
      vtr: JSON.stringify([VECTORS_OF_TRUST.AUTH_MEDIUM]),
      ui_locales: LOCALE.EN
    };

    // Include claims that are being requested
    // if(CLAIMS) {
    //   authorizationParameters.claims = JSON.stringify(CLAIMS);
    // }
    
    // Construct the url and redirect on to the authorization endpoint
    const authorizationUrl = client.authorizationUrl(authorizationParameters);
    console.log(authorizationUrl);
    // Redirect to the authorization server
    res.redirect(authorizationUrl);
  });

  router.get("/oauth/verify", (req: Request, res: Response) => {

    // Calculate the redirect URL the should be returned to after completing the OAuth flow
    const redirectUri =
    configuration.authorizeRedirectUri ||
    getRedirectUri(req);

    // Generate values that protect the flow from replay attacks.
    const nonce = generators.nonce();
    const state = generators.state();
    
    // Store the nonce and state in a session cookie so it can be checked in callback
    res.cookie(NONCE_COOKIE_NAME, nonce, {
      httpOnly: true,
    });
    res.cookie(STATE_COOKIE_NAME, state, {
      httpOnly: true,
    });

    const authorizationParameters: AuthorizationParameters = {
      redirect_uri: redirectUri,
      response_type: "code",
      scope: SCOPES.join(" "),
      state: hash(state),
      nonce: hash(nonce),
      vtr: JSON.stringify([VECTORS_OF_TRUST.AUTH_MEDIUM_IDENTITY_MEDIUM]),
      ui_locales: LOCALE.EN
    };

    // Include claims that are being requested
    if(CLAIMS) {
      authorizationParameters.claims = JSON.stringify(CLAIMS);
    }
    
    // Construct the url and redirect on to the authorization endpoint
    const authorizationUrl = client.authorizationUrl(authorizationParameters);
    console.log(authorizationUrl);
    // Redirect to the authorization server
    res.redirect(authorizationUrl);
  });
    
  // Callback receives the code and state from the authorization server
  router.get("/oauth/callback", asyncHandler(async (req: Request, res: Response) => {
      // Check for an error
      if (req.query["error"]) {
        throw new Error(`${req.query.error} - ${req.query.error_description}`);
      }

      // Get all the parameters to pass to the token exchange endpoint
      const redirectUri =
        configuration.authorizeRedirectUri ||
        getRedirectUri(req);
      const params = client.callbackParams(req);
      const nonce = req.cookies[NONCE_COOKIE_NAME];
      const state = req.cookies[STATE_COOKIE_NAME];

      // Exchange the access code in the url parameters for an access token.
      // The access token is used to authenticate the call to get userinfo.
      const tokenSet = await client.callback(redirectUri, params, {
        state: hash(state),
        nonce: hash(nonce),
      });

      // Call the userinfo endpoint then retreive the results of the flow.
      const result = await getResult(res, ivPublicKey, client, tokenSet);

      // Display the results.
      res.render("result.njk", { result });
    })
  );

  // Use the refresh token to get a new an access token and update the results.
  router.post("/oauth/refresh", urlencoded({extended:true}), asyncHandler(async (req: Request, res: Response) => {
      const refreshToken = req.body.token;

      // Exchange the refresh token for a new access token.
      const tokenSet = await client.refresh(refreshToken);

      // Call the userinfo endpoint the retrieve the results of the flow.
      const result = await getResult(res, ivPublicKey, client, tokenSet);

      // Display the results.
      res.render("result.njk", result);
    })
  );

  router.get("/oauth/logout", (req: Request, res: Response) => {
    // this handles the logout button click event
    const redirectUri = configuration.postLogoutRedirectUri;

    const state = req.cookies[STATE_COOKIE_NAME];
    const idtoken = req.cookies[ID_TOKEN_COOKIE_NAME];
    const logoutUrl = client.endSessionUrl({
      post_logout_redirect_uri: redirectUri,
      id_token_hint: idtoken,    
      state: hash(state)
    })
    console.log(logoutUrl);
    res.redirect(logoutUrl);
  });

  router.get("/logged-out", (req: Request, res: Response) => {
    // this handles the logout redirect
    const message = {text: "You have been logged out." }; 
    res.render("logged-out.njk", message);
  });

  router.post("/back-channel-logout",asyncHandler(async (req: Request, res: Response) => {

      const logoutToken = await verifyLogoutToken(req);

      if (logoutToken && validateLogoutTokenClaims(logoutToken, req)) {
        //await destroyUserSessions(token.sub, req.app.locals.sessionStore);
        res.sendStatus(HTTP_STATUS_CODES.OK);
        //const logoutToken = JSON.stringify(decodeJwt(token), null, 2)
        // const message = {text: "You have been logged out by a back-channel message." }; 
        // res.render("back_channel-logout.njk", { logoutToken, message });;
      }
      else {
        res.sendStatus(HTTP_STATUS_CODES.UNAUTHORIZED);
      }
  }));

  async function verifyLogoutToken(req: Request): Promise<LogoutToken | undefined> {
    if (!(req.body && Object.keys(req.body).includes("logout_token"))) {
      return undefined;
    }

    try {
      const JWKS = createRemoteJWKSet(new URL(issuer.metadata.jwks_uri!));

      const { payload, protectedHeader } = await jwtVerify( req.body.logout_token, JWKS, {
        issuer: issuer.issuer,
        audience: client.metadata.client_id,
        maxTokenAge: getLogoutTokenMaxAge(),
        clockTolerance: getTokenValidationClockSkew()
      });
  
      return payload as LogoutToken;
    } catch (e) {
      console.error(getErrorMessage(e));
      return undefined;
    }
  };

  function validateLogoutTokenClaims(token: LogoutToken, req: Request): boolean {
    if (!token.sub || /^\s*$/.test(token.sub)) {
      console.error(`Logout token does not contain a subject`);
      return false;
    }
    if (!token.events) {
      console.error(`Logout token does not contain any event`);
      return false;
    }
    if (!(BACK_CHANNEL_LOGOUT_EVENT in token.events)) {
      console.error(`Logout token does not contain correct event: ${token.events}`);
      return false;
    }
    if (Object.keys(token.events[BACK_CHANNEL_LOGOUT_EVENT]).length > 0) {
      console.error(`Logout token back-channel logout event is not an empty object`);
      return false;
    }
    return true;
  }

  return router;
};
