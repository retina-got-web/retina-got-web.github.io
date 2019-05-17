'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var bodyParser = _interopDefault(require('body-parser'));
var cookieSession = _interopDefault(require('cookie-session'));
var cookieParser = _interopDefault(require('cookie-parser'));
var uuid = _interopDefault(require('uuid'));
var stream = _interopDefault(require('stream'));
var bunyan = _interopDefault(require('bunyan'));
var express = require('express');
var express__default = _interopDefault(express);

const Writable = stream.Writable;


/*
 * Log to console
 */


const writableStream = Writable();

writableStream._write = (chunk, enc, next) => {
  let buffer = Buffer.from(chunk, enc);
  console.log(buffer.toString('utf8'));
  next();
};

function serialize_req(req) {
  return {
    method: req.method,
    protocol: req.protocol,
    hostname: req.hostname,
    path: req.path,
    base_url: req.baseUrl,
    query: req.query,
    ip: req.ip,
    body: req.body
  };
}

const logger = bunyan.createLogger({
  name: 'retina-trial-web',
  streams: [{
    level: process.env['NODE_ENV'] === 'development' ? 'debug' : 'info',
    stream: writableStream
  }],
  serializers: {
    err: bunyan.stdSerializers.err,
    req: serialize_req
  }
});

const create_req_child_logger = (req, req_uuid) => {
  // log AWS context https://www.npmjs.com/package/aws-serverless-express
  let apiGateway = req.apiGateway || {}; // attempt to log the current user (INSECURE)

  let user_email = '';
  let user_info_json = req.session.user_info_json;

  if (user_info_json) {
    let user_info = JSON.parse(user_info_json);
    user_email = user_info.email;
  } else {
    // Rely upon axios injection of this header
    let user_email_header = req.header('X-User-Email');

    if (user_email_header) {
      user_email = user_email_header;
    }
  }

  return logger.child({
    req_uuid,
    req: serialize_req(req),
    context: apiGateway.context || {},
    user_email
  });
};

var logger_1 = {
  logger,
  create_req_child_logger
};
var logger_3 = logger_1.create_req_child_logger;

const router = express.Router();

const Writable$1 = require('stream').Writable;
/*
 * Log to console
 */


const writableStream$1 = Writable$1();

writableStream$1._write = (chunk, enc, next) => {
  let buffer = Buffer.from(chunk, enc);
  console.log(buffer.toString('utf8')); // eslint-disable-line no-console

  next();
};

function create_express_app(nuxt, inject_early_middleware) {
  let app = express__default();

  if (inject_early_middleware) {
    app = inject_early_middleware(app);
  }

  app.use(cookieSession({
    name: 'session',
    keys: [process.env['SESSION_COOKIE_SECRET']],
    maxAge: 10 * 60 * 1000,
    // 10 minutes
    sameSite: true,
    httpOnly: true
  }));
  app.use(cookieParser());
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.locals.start_time_ms = new Date().getTime();
    res.locals.req_uuid = uuid();
    let logger = logger_3(req, res.locals.req_uuid);
    res.locals.logger = logger; // log the elapsed milliseconds for this request
    // https://www.lunchbadger.com/tracking-the-performance-of-express-js-routes-and-middleware/

    res.once('finish', () => {
      if (res.headersSent) {
        let log_data = {
          req,
          is_nuxt_asset: req.path && req.path.startsWith('/_nuxt/'),
          is_api: req.baseUrl && req.baseUrl.startsWith('/api/'),
          'status': res.statusCode,
          elapsed_ms: new Date().getTime() - res.locals.start_time_ms
        };

        if (res.locals.err) {
          log_data.err = res.locals.err;
          logger.error(log_data, 'COMPLETED_REQUEST_ERROR');
        } else {
          logger.info(log_data, 'COMPLETED_REQUEST');
        }
      }
    });
    next();
  });
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use('/api', router);
  app.use(nuxt.render);
  /*
     * error handling
     * https://expressjs.com/en/guide/error-handling.html
     */

  app.use((err, req, res, next) => {
    // setting this logs this request as an error in the finish handler
    res.locals.err = err;
    res.status(500).send({
      error: 'Error ' + err
    });
  });
  return app;
}

module.exports = {
  create_express_app
};
