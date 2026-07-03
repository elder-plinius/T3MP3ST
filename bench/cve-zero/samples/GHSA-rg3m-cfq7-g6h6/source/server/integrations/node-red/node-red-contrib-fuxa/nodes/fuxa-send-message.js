module.exports = function(RED) {
    function FuxaSendMessageNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                var address = config.address || msg.address;
                var subject = config.subject || msg.subject;
                var message = config.message || msg.message || msg.payload;
                if (address && subject && message) {
                    await fuxa.sendMessage(address, subject, message);
                    node.send(msg);
                } else {
                    node.error('Missing address, subject, or message', msg);
                }
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("send-message", FuxaSendMessageNode);
}