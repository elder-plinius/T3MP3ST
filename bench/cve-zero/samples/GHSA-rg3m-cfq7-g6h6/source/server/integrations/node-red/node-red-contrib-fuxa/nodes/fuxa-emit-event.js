module.exports = function(RED) {
    function FuxaEmitEventNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', function(msg) {
            try {
                fuxa.emit(config.eventType, msg.payload);
                node.send(msg);
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("emit-event", FuxaEmitEventNode);
}