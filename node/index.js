var zmq = require('zmq');
var msgpack = require('msgpack');
var sock = zmq.socket('sub');

sock.connect('tcp://localhost:3000');
sock.subscribe('');

sock.on('message', function(data) {
  console.log(': received data ');
  var msg = msgpack.unpack(data);
  console.log(msg);
});

