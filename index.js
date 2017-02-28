/*
 * WebSSH2 - Web to SSH2 gateway
 * Bill Church - https://github.com/billchurch - April 2016
 * 
 */

var express = require('express');
var app = express();
var cookieParser = require('cookie-parser')
var server = require('http').Server(app);
var io = require('socket.io')(server);
var path = require('path');
var fs = require('fs');
var basicAuth = require('basic-auth');
var ssh = require('ssh2');
var readConfig = require('read-config'),
    config = readConfig(__dirname + '/config.json');
var myError = " - ";
var bodyParser = require('body-parser');

function logErrors(err, req, res, next) {
    console.error(err.stack);
    next(err);
}

var authorizations = {};

server.listen({
    host: config.listen.ip,
    port: config.listen.port
}).on('error', function(err) {
    if (err.code === 'EADDRINUSE') {
        config.listen.port++;
        console.log('Address in use, retrying on port ' + config.listen.port);
        setTimeout(function() {
            server.listen(config.listen.port);
        }, 250);
    }
});

/**
.use(function(req, res, next) {
    var myAuth = basicAuth(req);
    if (myAuth === undefined) {
        res.statusCode = 401;
        res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"');
        res.end('Username and password required for web SSH service.');
    } else if (myAuth.name == "") {
        res.statusCode = 401
        res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"');
        res.end('Username and password required for web SSH service.');
    } else {
        config.user.name = myAuth.name;
        config.user.password = myAuth.pass;
        next();
    }
})
 */

var html = fs.readFileSync(path.join(__dirname + '/public/client.html')).toString();

app.use(bodyParser.urlencoded({ extended: true })).use(express.static(__dirname + '/public')).use(cookieParser()).post('/ssh/host/:host?', function(req, res) {
    var auth = {
        ssh: {
            port: config.ssh.port
        },
        header: {
            text: config.header.text,
            background: config.header.background
        },
        options: {
            challengeButton: config.options.challengeButton
        },
        user: {}
    };
    auth.ssh.host = req.params.host;
    auth.user.name = req.body.username;
    auth.user.password = req.body.password;
    if (typeof req.body.port !== 'undefined' && req.body.port !== null) { auth.ssh.port = req.body.port; }
    if (typeof req.body.header !== 'undefined' && req.body.header !== null) { auth.header.text = req.body.header; }
    if (typeof req.body.headerBackground !== 'undefined' && req.body.headerBackground !== null) { auth.header.background = req.body.headerBackground; }
    console.log('webssh2 Login: user=' + auth.user.name + ' from=' + req.ip + ' host=' + auth.ssh.host + ' port=' + auth.ssh.port + ' sessionID=' + req.headers['sessionid'] + ' allowreplay=' + req.headers['allowreplay']);
    console.log('Headers: ' + JSON.stringify(req.headers));
    auth.options.allowreplay = req.headers['allowreplay'];

    res.send(html.replace('<!-- authorization -->', JSON.stringify(auth)));

}).use('/style', express.static(__dirname + '/public')).use('/src', express.static(__dirname + '/node_modules/xterm/dist')).use('/addons', express.static(__dirname + '/node_modules/xterm/dist/addons'));

io.on('connection', function(socket) {
    socket.on('authorize', function(data) {

        console.log('authorize', data);

        var auth = JSON.parse(data);

        var conn = new ssh();
        conn.on('banner', function(d) {
            //need to convert to cr/lf for proper formatting
            d = d.replace(/\r?\n/g, "\r\n");
            socket.emit('data', d.toString('binary'));
        }).on('ready', function() {
            socket.emit('title', 'ssh://' + auth.ssh.host);
            socket.emit('headerBackground', auth.header.background);
            socket.emit('header', auth.header.text);
            socket.emit('footer', 'ssh://' + auth.user.name + '@' + auth.ssh.host + ':' + auth.ssh.port);
            socket.emit('status', 'SSH CONNECTION ESTABLISHED');
            socket.emit('statusBackground', 'green');
            socket.emit('allowreplay', auth.options.allowreplay)
            conn.shell(function(err, stream) {
                if (err) {
                    console.log(err.message);
                    myError = myError + err.message
                    return socket.emit('status', 'SSH EXEC ERROR: ' + err.message).emit('statusBackground', 'red');
                }
                socket.on('data', function(data) {
                    stream.write(data);
                });
                socket.on('control', function(controlData) {
                    switch (controlData) {
                        case 'replayCredentials':
                            stream.write(auth.user.password + '\n');
                        default:
                            console.log('controlData: ' + controlData);
                    };
                });
                stream.on('data', function(d) {
                    socket.emit('data', d.toString('binary'));
                }).on('close', function(code, signal) {
                    console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);
                    conn.end();
                }).stderr.on('data', function(data) {
                    console.log('STDERR: ' + data);
                });
            });
        }).on('end', function() {
            socket.emit('status', 'SSH CONNECTION CLOSED BY HOST' + myError);
            socket.emit('statusBackground', 'red');
        }).on('close', function() {
            socket.emit('status', 'SSH CONNECTION CLOSE' + myError);
            socket.emit('statusBackground', 'red');
        }).on('error', function(err) {
            myError = myError + err
            socket.emit('status', 'SSH CONNECTION ERROR' + myError);
            socket.emit('statusBackground', 'red');
            console.log('on.error' + myError);
        }).on('keyboard-interactive', function(name, instructions, instructionsLang, prompts, finish) {
            console.log('Connection :: keyboard-interactive');
            finish([auth.user.password]);
        }).connect({
            host: auth.ssh.host,
            port: auth.ssh.port,
            username: auth.user.name,
            password: auth.user.password,
            tryKeyboard: true,
            // some cisco routers need the these cipher strings
            algorithms: {
                'cipher': ['aes128-cbc', '3des-cbc', 'aes256-cbc'],
                'hmac': ['hmac-sha1', 'hmac-sha1-96', 'hmac-md5-96']
            }
        });
    });
});
