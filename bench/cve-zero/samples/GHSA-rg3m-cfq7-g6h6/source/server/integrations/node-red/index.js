// server/integrations/node-red/index.js
// Optional Node-RED integration: mount only if the package is installed.

const fs = require('fs');
const path = require('path');

function tryRequireNodeRed() {
    try {
        // Fast check whether the module is resolvable
        require.resolve('node-red');
        // Load it only after resolve succeeds
        // (keeps main process clean when not installed)
        // eslint-disable-next-line global-require
        return require('node-red');
    } catch {
        return null;
    }
}

async function mountNodeRedIfInstalled({ app, server, settings, runtime, logger, authJwt, events }) {
    const RED = tryRequireNodeRed();
    if (!RED) {
        logger.info('[Node-RED] Package not installed. Skipping Node-RED initialization.');
        // Do not register any /nodered routes; default 404 is fine.
        return;
    }

    // Prepare Node-RED userDir for flows and settings
    const userDir = path.join(settings.workDir, 'node-red');
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }

    // Minimal Node-RED settings; extend only what is really needed
    const redSettings = {
        httpAdminRoot: '/nodered/',
        // Serve Node-RED HTTP nodes under /dashboard to avoid intercepting FUXA routes
        httpNodeRoot: '/dashboard',
        userDir,
        nodesDir: [path.join(__dirname, 'node-red-contrib-fuxa')],
        flowFile: 'flows.json',
        editorTheme: {
            notifications: { enabled: false },
            tours: { enabled: false },
        },
        // Dashboard will be exposed at /dashboard/...
        ui: { path: '/' },
        // Values used by FlowFuse dashboard's ui_base.js for layout saves
        // These mirror the FUXA HTTP bind address so Node-RED can call its own /nodered/flows API
        uiHost: settings.uiHost,
        uiPort: settings.uiPort,
        functionGlobalContext: {
            // Expose essential FUXA runtime helpers
            fuxa: {
                runtime,
                getTag: require(path.join(settings.appDir, 'runtime/devices')).getTagValue,
                setTag: require(path.join(settings.appDir, 'runtime/devices')).setTagValue,
                getDaq: require(path.join(settings.appDir, 'runtime/storage/daqstorage')).getNodeValues,
                getTagId: require(path.join(settings.appDir, 'runtime/devices')).getTagId,
                getHistoricalTags: require(path.join(settings.appDir, 'runtime/devices')).getHistoricalTags,
                emit: events.emit.bind(events),
                on: events.on.bind(events),
                removeListener: events.removeListener.bind(events),
                sendMessage: async (address, subject, message) =>
                    await runtime.notificatorMgr.sendMailMessage(null, address, subject, message, null, null),
                getAlarms: async () => await runtime.alarmsMgr.getAlarmsValues(null, -1),
                getHistoryAlarms: async (start, end) => {
                    const query = { start, end };
                    return runtime.alarmsMgr.getAlarmsHistory(query, -1);
                },
                ackAlarm: async (alarmName, types) => {
                    const utils = require(path.join(settings.appDir, 'runtime/utils'));
                    const sep = runtime.alarmsMgr.getIdSeparator();
                    if (alarmName.indexOf(sep) === -1 && !utils.isNullOrUndefined(types)) {
                        const results = [];
                        for (const t of types) {
                            const alarmId = `${alarmName}${sep}${t}`;
                            results.push(await runtime.alarmsMgr.setAlarmAck(alarmId, null, -1));
                        }
                        return results;
                    }
                    return runtime.alarmsMgr.setAlarmAck(alarmName, null, -1);
                },
                getScripts: async () => {
                    const scripts = await runtime.project.getScripts();
                    return scripts ? scripts.map(s => ({ id: s.id, name: s.name })) : [];
                },
                runScript: async (scriptName, params) => {
                    const scripts = await runtime.project.getScripts();
                    const script = scripts?.find(s => s.name === scriptName);
                    if (!script) throw new Error(`Script '${scriptName}' not found`);
                    return runtime.scriptsMgr.runScript(script, null, params);
                },
            },

            // Common Node.js stdlib modules handy in flows
            fs: require('fs').promises,
            fsSync: require('fs'),
            path: require('path'),
            util: require('util'),
            os: require('os'),
            http: require('http'),
            https: require('https'),
            dgram: require('dgram'),
            dns: require('dns'),
            url: require('url'),
            querystring: require('querystring'),
            crypto: require('crypto'),
            zlib: require('zlib'),
            stream: require('stream'),
            events: require('events'),
            buffer: require('buffer'),
            sqlite3: require('sqlite3'),
            serialport: require('serialport'),
            // Dangerous modules are opt-in only (see settings.nodeRedUnsafeModules)
            ...(settings.nodeRedUnsafeModules ? {
                child_process: require('child_process'),
                net: require('net'),
            } : {}),
        },
    };

    // Initialize Node-RED on the existing HTTP server (must be done before server.listen)
    RED.init(server, redSettings);

    const getCookieValue = (req, name) => {
        const cookieHeader = req.headers.cookie;
        if (!cookieHeader) return null;
        const cookies = cookieHeader.split(';');
        for (const cookie of cookies) {
            const [key, ...rest] = cookie.trim().split('=');
            if (key === name) {
                return rest.join('=');
            }
        }
        return null;
    };

    const verifyApiKey = (runtimeRef, apiKey) => {
        return runtimeRef.apiKeys.getApiKeys().then(stored => {
            const now = Date.now();
            return stored.find(k => {
                if (!k || k.key !== apiKey || k.enabled === false) {
                    return false;
                }
                if (!k.expires) {
                    return true;
                }
                const expiresAt = new Date(k.expires).getTime();
                return !isNaN(expiresAt) && expiresAt > now;
            });
        });
    };

    // Allow public dashboard UI and socket.io; require JWT or API key for admin/editor/flows when security is enabled
    const allowDashboard = (req, res, next) => {
        const url = req.originalUrl || req.url || req.path;

        // Public dashboard UI and its HTTP APIs (served from httpNodeRoot/ui.path)
        if (url.includes('/dashboard') || url.includes('/socket.io')) return next();

        if (!settings.secureEnabled || settings.nodeRedAuthMode === 'legacy-open') {
            return next();
        }

        const apiKey = req.headers['x-api-key'];
        if (apiKey) {
            return verifyApiKey(runtime, apiKey)
                .then(validKey => {
                    if (!validKey) {
                        return res.status(401).json({ error: "unauthorized_error", message: "Invalid API Key" });
                    }
                    return next();
                })
                .catch(err => {
                    logger.error(`api-key validation failed: ${err}`);
                    return res.status(500).json({ error: "unexpected_error", message: "ApiKey validation failed" });
                });
        }

        const headerToken = req.headers['x-access-token'];
        const queryToken = req.query?.token;
        const cookieToken = getCookieValue(req, 'nodered_auth');
        // Prefer explicit tokens over cookie to avoid stale cookie blocking valid logins
        const token = headerToken || queryToken || cookieToken;
        if (!token) {
            return res.status(401).json({ error: "unauthorized_error", message: "Authentication required!" });
        }

        return authJwt.verify(token)
            .then(() => {
                if (queryToken) {
                    res.cookie('nodered_auth', token, {
                        httpOnly: true,
                        sameSite: 'lax',
                        secure: !!settings.https,
                    });
                    if (req.method === 'GET') {
                        const cleanUrl = new URL(req.originalUrl, `http://${req.headers.host}`);
                        cleanUrl.searchParams.delete('token');
                        return res.redirect(cleanUrl.pathname + cleanUrl.search);
                    }
                }
                return next();
            })
            .catch(() => {
                if (cookieToken) {
                    res.clearCookie('nodered_auth');
                }
                return res.status(401).json({ error: "unauthorized_error", message: "Invalid token!" });
            });
    };

    // Mount Node-RED admin/editor under /nodered; HTTP nodes (including dashboard)
    // are served from httpNodeRoot ('/dashboard') so they appear at /dashboard/... etc.
    app.use('/nodered', allowDashboard, RED.httpAdmin);
    app.use('/dashboard', allowDashboard, RED.httpNode);

    await RED.start();

    RED.httpAdmin.get('/fuxa/devices', function(req, res) {
        const devices = runtime.project.getDevices();
        const result = [];
        for (const id in devices) {
            const device = devices[id];
            const tags = [];
            for (const tagId in device.tags) {
                tags.push({ id: tagId, name: device.tags[tagId].name });
            }
            result.push({ id: device.id, name: device.name, tags });
        }
        res.json(result);
    });

    RED.httpAdmin.get('/fuxa/scripts', async function(req, res) {
        try {
            const scripts = await runtime.project.getScripts();
            const result = scripts ? scripts.map(script => ({ id: script.id, name: script.name })) : [];
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    RED.httpAdmin.get('/fuxa/views', async function(req, res) {
        try {
            const project = await runtime.project.getProject();
            const result = project && project.hmi && project.hmi.views ?
                project.hmi.views.map(view => ({ id: view.id, name: view.name })) : [];
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    RED.httpAdmin.get('/fuxa/alarms', async function(req, res) {
        try {
            const alarms = await runtime.project.getAlarms();
            const result = alarms ?
                alarms.map(alarm => ({ id: alarm.id, name: alarm.name })) : [];
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // set api to listen (moved here to avoid rate limiting Node-RED routes)
    if (settings.disableServer !== false) {
        // Catch-all route for SPA - serve Angular index.html for client routes
        // Exclude API routes and static assets
        app.get('*', (req, res, next) => {
            // Skip API routes and static assets
            if (req.path.startsWith('/api/') ||
                req.path.includes('.') ||
                req.path.startsWith('/nodered') ||
                req.path.startsWith('/dashboard')) {
                return next();
            }
            res.sendFile(path.join(settings.httpStatic, 'index.html'));
        });
    }

    logger.info('[Node-RED] Started at /nodered');
}

module.exports = { mountNodeRedIfInstalled };
