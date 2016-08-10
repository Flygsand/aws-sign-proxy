var http = require('http')
  , winston = require('winston')
  , connect = require('connect')
  , bodyParser = require('body-parser')
  , basicAuth = require('basic-auth')
  , httpProxy = require('http-proxy')
  , AWS = require('aws-sdk')
  , parseArgs = require('minimist');

function proxy(endpoint, region, service) {
  var proxy = httpProxy.createProxy({
    secure: true,
    changeOrigin: true,
    target: endpoint.href
  });

  proxy.on('proxyReq', function(proxyReq, req, res, options) {
    var awsReq = new AWS.HttpRequest(endpoint);
    awsReq.method = proxyReq.method;
    awsReq.path = proxyReq.path;
    awsReq.headers['Host'] = endpoint.host;
    awsReq.headers['presigned-expires'] = false;
    awsReq.region = region;
    if (Buffer.isBuffer(req.body)) {
      awsReq.body = req.body;
    }

    var signer = new AWS.Signers.V4(awsReq, service);
    signer.addAuthorization({
      accessKeyId: req.accessKeyId,
      secretAccessKey: req.secretAccessKey
    }, new Date());

    proxyReq.setHeader('Host', awsReq.headers['Host']);
    proxyReq.setHeader('X-Amz-Date', awsReq.headers['X-Amz-Date']);
    proxyReq.setHeader('Authorization', awsReq.headers['Authorization']);
  });

  return function(req, res) {
    var opts = {};
    if (Buffer.isBuffer(req.body)) {
      opts.buffer = AWS.util.buffer.toStream(req.body);
    }

    proxy.web(req, res, opts);
  };
}

function credentials() {
  return function(req, res, next) {
    var creds = basicAuth(req);
    if (!creds) {
      res.statusCode = 401;
      res.setHeader('WWW-Authenticate', 'Basic realm=aws-sign-proxy');
      res.end();
    } else {
      req.accessKeyId = creds.name;
      req.secretAccessKey = creds.pass;
      next();
    }
  };
}

function exitBadArgument(arg) {
  winston.error('missing or invalid argument ' + arg);
  process.exit(1);
}

function main(args) {
  var port = parseInt(args.port || process.env['PORT']);
  if (isNaN(port)) {
    exitBadArgument('port');
  }

  ['endpoint', 'region', 'service'].forEach(function(arg) {
    if (!(arg in args) && !(arg.toUpperCase().replace('-', '_') in process.env)) {
      exitBadArgument(arg);
    }
  });

  var app = connect();
  app.use(credentials());
  app.use(bodyParser.raw({type: '*/*'}));
  app.use(proxy(
    new AWS.Endpoint(args.endpoint || process.env['ENDPOINT']),
    args.region || process.env['REGION'],
    args.service || process.env['SERVICE']
  ));

  winston.info('listening on port ' + port)
  http.createServer(app).listen(port);
}

main(parseArgs(process.argv.slice(2)));
