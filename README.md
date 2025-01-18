# Amble app prototype

# WIP

## user account service

 * basic code logic
 * configure nats-server accordingly (storage dir, limits, ...)
 * ad nkeys based auth - so there will be a client, who can _read_ from user data for login purposes
 * multi-tenancy model
 * at least a basic admin interface - for a display if nothing
 * duplicate accounts

# TODO

## General

 * create authenticated nats client for web - server side events - this will use abmle's JWT
 * create authenticated nats client from command line - this will use IDP like github
 * publish events from local to web through NATS

## JWT

 * generate and validate jti's - detecting the token was reverted
 * connect claims uid to account service

# Done

 * unit test of gihub login
 * JWT using EdDSA + ED25519
 * csfr protection
 * github oauth2 login

# Secrets

 *   `github.secrets.json` client_id+client_secret for Github Oauth
 *   `google.secrets.json` client_id+client_secret for Google Oauth
 *   `jwt.ed25519.seed` 32bit random seed for ed25519 private key used for
       signing JWTs. Generate using a crypto safe way as `openssl rand -out
       secrets/jwt.secret 32`
