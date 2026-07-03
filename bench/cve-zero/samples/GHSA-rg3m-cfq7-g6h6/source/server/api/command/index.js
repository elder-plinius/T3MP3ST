/**
 * 'api/command': Command API to process command like build Report
 */

var express = require("express");
const authJwt = require('../jwt-helper');
const fs = require('fs');
const path = require('path');
const { resolveWithin } = require('../path-helper');
var runtime;
var secureFnc;
var checkGroupsFnc;

module.exports = {
    init: function (_runtime, _secureFnc, _checkGroupsFnc) {
        runtime = _runtime;
        secureFnc = _secureFnc;
        checkGroupsFnc = _checkGroupsFnc;
    },
    app: function () {
        var commandApp = express();
        commandApp.use(function (req, res, next) {
            if (!runtime.project) {
                res.status(404).end();
            } else {
                next();
            }
        });

        /**
         * GET download
         */
        commandApp.get('/api/download', secureFnc, function(req, res){
            const permission = checkGroupsFnc(req);
            if (res.statusCode === 403) {
                runtime.logger.error("api post command: Tocken Expired");
            } else if (!authJwt.haveAdminPermission(permission)) {
                res.status(401).json({error:"unauthorized_error", message: "Unauthorized!"});
                runtime.logger.error("api post command: Unauthorized");
            } else {
                if (req.query.cmd === CommanTypeEnum.reportDownload) {
                    try {
                        var reportBase = runtime.settings.reportsDir;
                        if (!fs.existsSync(reportBase)) {
                            reportBase = path.join(process.cwd(), runtime.settings.reportsDir);
                        }
                        const resolvedReport = resolveWithin(reportBase, req.query.name);
                        if (!resolvedReport) {
                            res.status(400).json({ error: "invalid_path", message: "Invalid report file." });
                            return;
                        }
                        const reportPath = resolvedReport.resolvedTarget;
                        if (fs.existsSync(reportPath)) {
                            res.sendFile(reportPath, (err) => {
                                if (err) {
                                    runtime.logger.error("api get download: " + err);
                                }
                            });
                        } else {
                            res.status(400).json({ error: "not_found", message: 'report not found!'});
                            runtime.logger.error("api get download: " + 'report not found!');
                        }
                    } catch (error) {
                        res.status(400).json({ error: 'error', message: error});
                        runtime.logger.error("api get download: " + error);
                    }
                } else {
                    res.status(400).json({ error: "not_found", message: 'command not found!'});
                }
            }
        });

        /**
         * GET get tags values
         */
        commandApp.get("/api/getTagValue", secureFnc, async function (req, res, next) {
            const permission = checkGroupsFnc(req);
            if (res.statusCode === 403) {
                runtime.logger.error("api get getTagValue: Tocken Expired");
            } else if (!authJwt.haveAdminPermission(permission) && !runtime.scriptsMgr.isAuthorisedByScriptName(req.query.sourceScriptName, permission)) {
                res.status(400).json({error:"unauthorized_error", message: "Unauthorized!"});
                runtime.logger.error("api get getTagValue: Unauthorized");
            } else {
                try {
                    var tagsIds = JSON.parse(req.query.ids);
                    if (tagsIds) {
                        var errors = '';
                        var result = [];
                        for (const tagId of tagsIds) {
                            try {
                                const value = runtime.devices.getTagValue(tagId, true);
                                if (value) {
                                    result.push(value);
                                } else {
                                    result.push({id: tagId, value: null});
                                    errors += `${tagId}; `;
                                }
                            } catch (err) {
                                errors += `${tagId}: ${err}`;
                            }
                        }
                        if (errors) {
                            runtime.logger.error("api get getTagValue: " + 'id not found!' + errors);
                        }
                        res.json(result);
                    } else {
                        res.status(400).json({ error: "not_found", message: 'tag id not found!'});
                        runtime.logger.error("api get getTagValue: " + 'id not found!');
                    }
                } catch (error) {
                    res.status(400).json({ error: "error", message: error});
                    runtime.logger.error("api get getTagValue: " + error);
                }
            }
        });

        /**
         * POST set tags values
         */
        commandApp.post("/api/setTagValue", secureFnc, async function (req, res, next) {
            const permission = checkGroupsFnc(req);
            if (res.statusCode === 403) {
                runtime.logger.error("api post setTagValue: Tocken Expired");
            } else if (!authJwt.haveAdminPermission(permission)) {
                res.status(401).json({error:"unauthorized_error", message: "Unauthorized!"});
                runtime.logger.error("api post setTagValue: Unauthorized");
            } else {
                try {
                    if (req.body.tags) {
                        var errors = '';
                        for (const tag of req.body.tags) {
                            try {
                                if (!await runtime.devices.setTagValue(tag.id, tag.value)) {
                                    errors += `${tag.id} not found; `
                                }
                            } catch (err) {
                                errors += `${tag.id}: ${err}`;
                            }
                        }
                        if (errors) {
                            res.status(400).json({ error: "not_found", message: 'setTagValue Failed: ' + errors});
                            runtime.logger.error("api post setTagValue Failed:" + errors);
                        } else {
                            res.end();
                        }
                    } else {
                        res.status(400).json({ error: "not_found", message: 'no tags to set!'});
                        runtime.logger.error("api post setTagValue: " + 'id not found!');
                    }
                } catch (error) {
                    res.status(400).json({ error: "error", message: error});
                    runtime.logger.error("api post setTagValue: " + error);
                }
            }
        });

        return commandApp;
    }
}


const CommanTypeEnum = {
    reportDownload: 'REPORT-DOWNLOAD'
};
