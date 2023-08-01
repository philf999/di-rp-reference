import express, { Application, NextFunction, Request, Response } from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import path from "node:path";
import { nunjucks } from "../shared/utils/nunjucks";
import { auth } from "../shared/auth";
import { getNodeEnv } from "../shared/utils/config"; 
export const app: Application = express();
const port = process.env.NODE_PORT || 3000;

declare module 'express-session' {
  interface SessionData {
    user: any;
  }
};

(async () => {
  // Configure Nunjucks view engine
  const nunjucksPath = path.join(__dirname, "../shared/views");
  nunjucks(app, nunjucksPath);

  // Configure serving static assets like images and css
  const publicPath = path.join(__dirname, "../../public");
  app.use(express.static(publicPath));

  // Configure body-parser
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  // Configure parsing cookies - required for storing nonce in authentication
  app.use(cookieParser());
  app.use(session({
    name: process.env.SESSION_NAME + "-session",
    secret: process.env.SESSION_SECRET!, 
    cookie: {
      maxAge: 1000 * 120 * 60, // 2 hours
      secure: false,
      httpOnly: true
    },
    resave: false,
    saveUninitialized: true
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

  function authenticate(req: Request, res: Response, next: NextFunction) {
    if (req.session.user) {
      next() 
    }
    else {
      res.redirect("/oauth/login")
    }
  }

  // Application routes
  app.get("/camelids", authenticate, (req: Request, res: Response) => {
    // res.render("home.njk", { serviceIntroMessage: process.env.SERVICE_INTRO_MESSAGE, serviceHeading: process.env.SERVICE_HEADING});
    res.render(
      "dashboard.njk", 
      { 
        authenticated: true, 
        isProduction: getNodeEnv() == "development" ? false : true, 
        navigationItems: [{
          href: "/oauth/logout",
          text: "Sign out of service",
          id: "serviceSignOut"
      },]
    })
  });

  app.get(`${process.env.ROOT_ROUTE}`, (req: Request, res: Response) => {
    res.render("home.njk", { serviceIntroMessage: process.env.SERVICE_INTRO_MESSAGE, serviceHeading: process.env.SERVICE_HEADING, serviceName: process.env.SESSION_NAME, serviceType: process.env.SERVICE_TYPE });
  });

  app.get(`${process.env.ROOT_ROUTE}/logged-in`,authenticate, (req: Request, res: Response) => {
    res.render("service-home.njk", { serviceIntroMessage: process.env.SERVICE_INTRO_MESSAGE, serviceHeading: process.env.SERVICE_HEADING, serviceName: process.env.SESSION_NAME, serviceType: process.env.SERVICE_TYPE });
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
