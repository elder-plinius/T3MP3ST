module.exports = function(RED) {
    function FuxaGetTagIdNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                var tagName = config.tagName || msg.tagName;
                if (tagName) {
                    var tagId = fuxa.getTagId(tagName, null);
                    msg.payload = tagId;
                    node.send(msg);
                } else {
                    node.error('Tag name not specified', msg);
                }
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("get-tag-id", FuxaGetTagIdNode);
}