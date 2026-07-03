module.exports = function(RED) {
    function FuxaGetDaqNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                // Prefer config.tagId, fallback to config.tag for backward compatibility
                var tagId = config.tagId;
                if (!tagId && config.tag) {
                    // Backward compatibility: old nodes use tag.name, need to convert to tagId
                    tagId = fuxa.getTagId(config.tag, null);
                }
                
                if (tagId) {
                    var fromts = config.from || msg.from || Date.now() - 3600000; // default 1 hour ago
                    var tots = config.to || msg.to || Date.now();
                    var data = await fuxa.getDaq(tagId, fromts, tots);
                    msg.payload = data;
                    node.send(msg);
                } else {
                    node.error('Tag not found: ' + (config.tag || config.tagId), msg);
                }
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("get-daq", FuxaGetDaqNode);
}