import express, { Application, NextFunction, Request, Response } from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import path from "node:path";
import { nunjucks } from "./config/nunjucks";
import { auth } from "./config/auth";

export const app: Application = express();
const port = process.env.NODE_PORT || 3000;

(async () => {
  // Configure Nunjucks view engine
  nunjucks(app, path.join(__dirname, "views"));

  // Configure serving static assets like images and css
  app.use(express.static(path.join(__dirname, "public")));

  // Configure body-parser
  app.use(express.json());
  app.use(express.urlencoded());
  
  // Configure parsing cookies - required for storing nonce in authentication
  app.use(cookieParser());
  app.use(session({
    name: "camelid-dept",
    secret: "Shh, its a secret!", 
    cookie: {
      // maxAge: 1000 * 120 * 60,
      secure: false,
      httpOnly: true
    },
    resave: false,
    saveUninitialized: false
  }));

  // Configure OpenID Connect Authentication middleware
  app.use(
    await auth({
      clientId: process.env.OIDC_CLIENT_ID,
      clientSecret: process.env.OIDC_CLIENT_SECRET,
      privateKey: process.env.OIDC_PRIVATE_KEY,
      discoveryEndpoint: process.env.OIDC_ISSUER_DISCOVERY_ENDPOINT,
      authorizeRedirectUri: process.env.OIDC_AUTHORIZE_REDIRECT_URI,
      postLogoutRedirectUri: process.env.OIDC_LOGOUT_REDIRECT_URI,
      identityVerificationPublicKey: process.env.IV_PUBLIC_KEY
    })
  );

  // Application routes
  app.get("/", (req: Request, res: Response) => {
    res.render("home.njk", { serviceIntroMessage: process.env.SERVICE_INTRO_MESSAGE, serviceHeading: process.env.SERVICE_HEADING});
  });

  // Generic error handler
  app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    res.render("error.njk", {
      name: err.name,
      message: err.message,
      stack: err.stack
    });
  });

  const server = await app.listen(port);
  const listeningAddress = server.address();
  if (listeningAddress && typeof listeningAddress === "object") {
    console.log(
      `Server listening ${listeningAddress.address}:${listeningAddress.port}`
    );
  }
})();
