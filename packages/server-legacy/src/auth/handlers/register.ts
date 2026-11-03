import crypto from 'node:crypto';

import type { OAuthClientInformationFull } from '@modelcontextprotocol/core-internal';
import { OAuthClientMetadataSchema } from '@modelcontextprotocol/core-internal';
import cors from 'cors';
import type { RequestHandler } from 'express';
import express from 'express';
import type { Options as RateLimitOptions } from 'express-rate-limit';
import { rateLimit } from 'express-rate-limit';

import type { OAuthRegisteredClientsStore } from '../clients';
import { InvalidClientMetadataError, InvalidRedirectUriError, OAuthError, ServerError, TooManyRequestsError } from '../errors';
import { allowedMethods } from '../middleware/allowedMethods';

export type ClientRegistrationHandlerOptions = {
    /**
     * A store used to save information about dynamically registered OAuth clients.
     */
    clientsStore: OAuthRegisteredClientsStore;

    /**
     * The number of seconds after which to expire issued client secrets, or 0 to prevent expiration of client secrets (not recommended).
     *
     * If not set, defaults to 30 days.
     */
    clientSecretExpirySeconds?: number;

    /**
     * Rate limiting configuration for the client registration endpoint.
     * Set to false to disable rate limiting for this endpoint.
     * Registration endpoints are particularly sensitive to abuse and should be rate limited.
     */
    rateLimit?: Partial<RateLimitOptions> | false;

    /**
     * Whether to generate a client ID before calling the client registration endpoint.
     *
     * If not set, defaults to true.
     */
    clientIdGeneration?: boolean;
};

const DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS = 30 * 24 * 60 * 60; // 30 days

/**
 * Redirect URIs registered through dynamic client registration must not carry a fragment
 * (RFC 6749 §3.1.2: "The endpoint URI MUST NOT include a fragment component") and must use
 * HTTPS unless the host is a loopback address (MCP authorization spec, *Communication Security*;
 * RFC 8252 §7.3 permits plain HTTP for loopback redirects in native-app flows).
 *
 * `SafeUrlSchema` cannot express either rule: it only refuses `javascript:`, `data:` and
 * `vbscript:`, and redirect URIs also have to be accepted by clients parsing server metadata.
 * The check therefore lives in the registration handler.
 */
function isLoopbackHost(hostname: string): boolean {
    const host = hostname.toLowerCase().replaceAll('[', '').replaceAll(']', '');
    return host === 'localhost' || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

export function findInvalidRedirectUri(redirectUris: readonly string[]): string | undefined {
    for (const uri of redirectUris) {
        if (uri.includes('#')) {
            return `redirect_uri "${uri}" must not contain a fragment (RFC 6749 §3.1.2)`;
        }

        let parsed: URL;
        try {
            parsed = new URL(uri);
        } catch {
            // SafeUrlSchema already rejected unparseable values; treat any survivor conservatively.
            return `redirect_uri "${uri}" could not be parsed`;
        }

        if (parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
            return `redirect_uri "${uri}" must use HTTPS unless the host is a loopback address`;
        }
    }

    return undefined;
}

export function clientRegistrationHandler({
    clientsStore,
    clientSecretExpirySeconds = DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS,
    rateLimit: rateLimitConfig,
    clientIdGeneration = true
}: ClientRegistrationHandlerOptions): RequestHandler {
    if (!clientsStore.registerClient) {
        throw new Error('Client registration store does not support registering clients');
    }

    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    // Configure CORS to allow any origin, to make accessible to web-based MCP clients
    router.use(cors());

    router.use(allowedMethods(['POST']));
    router.use(express.json());

    // Apply rate limiting unless explicitly disabled - stricter limits for registration
    if (rateLimitConfig !== false) {
        router.use(
            rateLimit({
                windowMs: 60 * 60 * 1000, // 1 hour
                max: 20, // 20 requests per hour - stricter as registration is sensitive
                standardHeaders: true,
                legacyHeaders: false,
                message: new TooManyRequestsError('You have exceeded the rate limit for client registration requests').toResponseObject(),
                ...rateLimitConfig
            })
        );
    }

    router.post('/', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');

        try {
            const parseResult = OAuthClientMetadataSchema.safeParse(req.body);
            if (!parseResult.success) {
                throw new InvalidClientMetadataError(parseResult.error.message);
            }

            const clientMetadata = parseResult.data;

            const invalidRedirectUri = findInvalidRedirectUri(clientMetadata.redirect_uris);
            if (invalidRedirectUri) {
                throw new InvalidRedirectUriError(invalidRedirectUri);
            }

            const isPublicClient = clientMetadata.token_endpoint_auth_method === 'none';

            // Generate client credentials
            const clientSecret = isPublicClient ? undefined : crypto.randomBytes(32).toString('hex');
            const clientIdIssuedAt = Math.floor(Date.now() / 1000);

            // Calculate client secret expiry time
            const clientsDoExpire = clientSecretExpirySeconds > 0;
            const secretExpiryTime = clientsDoExpire ? clientIdIssuedAt + clientSecretExpirySeconds : 0;
            const clientSecretExpiresAt = isPublicClient ? undefined : secretExpiryTime;

            let clientInfo: Omit<OAuthClientInformationFull, 'client_id'> & { client_id?: string } = {
                ...clientMetadata,
                client_secret: clientSecret,
                client_secret_expires_at: clientSecretExpiresAt
            };

            if (clientIdGeneration) {
                clientInfo.client_id = crypto.randomUUID();
                clientInfo.client_id_issued_at = clientIdIssuedAt;
            }

            clientInfo = await clientsStore.registerClient!(clientInfo);
            res.status(201).json(clientInfo);
        } catch (error) {
            if (error instanceof OAuthError) {
                const status = error instanceof ServerError ? 500 : 400;
                res.status(status).json(error.toResponseObject());
            } else {
                const serverError = new ServerError('Internal Server Error');
                res.status(500).json(serverError.toResponseObject());
            }
        }
    });

    return router;
}
