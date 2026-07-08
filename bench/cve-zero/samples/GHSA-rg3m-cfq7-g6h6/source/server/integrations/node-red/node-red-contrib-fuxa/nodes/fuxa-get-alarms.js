module.exports = function(RED) {
    function FuxaGetAlarmsNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        // Access FUXA functions from global context
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                var alarms = await fuxa.getAlarms();
                msg.payload = alarms;
                node.send(msg);
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("get-alarms", FuxaGetAlarmsNode);
}