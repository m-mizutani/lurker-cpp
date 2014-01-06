
/**
 * Module dependencies.
 */

var express = require('express');
var routes = require('./routes');
var user = require('./routes/user');
var http = require('http');
var path = require('path');

var app = express();

// all environments
app.set('port', process.env.PORT || 4000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.json());
app.use(express.urlencoded());
app.use(express.methodOverride());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

app.get('/', routes.index);
app.get('/users', user.list);

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});

var zmq = require('zmq');
var msgpack = require('msgpack');
var sock = zmq.socket('sub');

sock.connect('tcp://localhost:3000');
sock.subscribe('');

sock.on('message', function(data) {
  console.log(': received data ');
  var msg = msgpack.unpack(data);
  console.log(msg);
  mongodb.arp_req.save(msg);
});

var mongojs = require('mongojs');
var db_name = 'lurker';
var col_names = ['arp_req'];
var mongodb = mongojs.connect(db_name, col_names);
