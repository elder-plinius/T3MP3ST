module.exports = function(RED) {
    function FuxaSetTagDaqSettingsNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                // Prefer config.tagId, fallback to config.tag or msg.tag for backward compatibility
                var tagId = config.tagId;
                if (!tagId) {
                    var tagName = config.tag || msg.tag;
                    if (tagName) {
                        // Backward compatibility: old nodes use tag.name, need to convert to tagId
                        tagId = fuxa.getTagId(tagName, null);
                    }
                }
                
                if (tagId) {
                    var settings = {
                        enabled: config.enabled,
                        interval: config.interval,
                        deadband: config.deadband
                    };

                    // Override with message properties if provided
                    if (msg.enabled !== undefined) settings.enabled = msg.enabled;
                    if (msg.interval !== undefined) settings.interval = msg.interval;
                    if (msg.deadband !== undefined) settings.deadband = msg.deadband;

                    var result = await fuxa.setTagDaqSettings(tagId, settings);
                    msg.payload = result;
                    node.send(msg);
                } else {
                    node.error('Tag not found: ' + (config.tag || msg.tag || config.tagId), msg);
                }
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("set-tag-daq-settings", FuxaSetTagDaqSettingsNode);
}