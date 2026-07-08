module.exports = function(RED) {
    function FuxaGetDevicePropertyNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', async function(msg) {
            try {
                var deviceName = config.deviceName || msg.deviceName;
                var property = config.property || msg.property;

                if (deviceName && property) {
                    var result = await fuxa.getDeviceProperty(deviceName, property);
                    msg.payload = result;
                    node.send(msg);
                } else {
                    node.error('Device name and property not specified', msg);
                }
            } catch (err) {
                node.error(err, msg);
            }
        });
    }
    RED.nodes.registerType("get-device-property", FuxaGetDevicePropertyNode);
}