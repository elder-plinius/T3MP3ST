module.exports = function(RED) {
    function FuxaExecuteScriptNode(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        var fuxa = RED.settings.functionGlobalContext.fuxa;

        this.on('input', function(msg) {
            try {
                var scriptName = config.script;
                var params = msg.payload || {};

                if (scriptName) {
                    fuxa.runScript(scriptName, params).then(function(result) {
                        msg.payload = {
                            success: true,
                            script: scriptName,
                            result: result,
                            timestamp: new Date().toISOString()
                        };
                        node.send(msg);
                    }).catch(function(err) {
                        msg.payload = {
                            success: false,
                            script: scriptName,
                            error: err.message,
                            timestamp: new Date().toISOString()
                        };
                        node.send(msg);
                    });
                } else {
                    msg.payload = {
                        success: false,
                        error: 'No script selected',
                        timestamp: new Date().toISOString()
                    };
                    node.send(msg);
                }
            } catch (err) {
                msg.payload = {
                    success: false,
                    error: err.message,
                    timestamp: new Date().toISOString()
                };
                node.send(msg);
            }
        });
    }
    RED.nodes.registerType("execute-script", FuxaExecuteScriptNode);
}