module.exports = function(RED) {
    function FuxaGetHistoryAlarmsNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                var start = config.start || msg.start || Date.now() - 86400000; // default 1 day ago
                var end = config.end || msg.end || Date.now();

                // Convert string timestamps to numbers if needed (same as get-historical-tags)
                if (typeof start === 'string') {
                    start = new Date(start).getTime();
                }
                if (typeof end === 'string') {
                    end = new Date(end).getTime();
                }
                var alarms = await fuxa.getHistoryAlarms(start, end);
                msg.payload = alarms;
                node.send(msg);
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("get-history-alarms", FuxaGetHistoryAlarmsNode);
}