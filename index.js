/*!
 * express-session
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * Copyright(c) 2014 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * Module dependencies.
 * @private
 */

var cookie = require('cookie'); // cookie解析和序列化
var crc = require('crc').crc32; // 冗余检查 CRC JavaScript实现，参考pycrc
var debug = require('debug')('express-session');
var deprecate = require('depd')('express-session'); // 标记模块弃用
var parseUrl = require('parseurl'); // 解析URL 和url.parse类似，不过多次调用会缓存
var uid = require('uid-safe').sync // 创建一个加密的UID
  , onHeaders = require('on-headers') // 监听response写headers
  , signature = require('cookie-signature') // oauth1.0签名

var Session = require('./session/session')
  , MemoryStore = require('./session/memory')
  , Cookie = require('./session/cookie')
  , Store = require('./session/store')

// environment

var env = process.env.NODE_ENV;

/**
 * Expose the middleware.
 */

exports = module.exports = session;

/**
 * Expose constructors.
 */

exports.Store = Store;
exports.Cookie = Cookie;
exports.Session = Session;
exports.MemoryStore = MemoryStore;

/**
 * Warning message for `MemoryStore` usage in production.
 * @private
 */

var warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.';

/**
 * Node.js 0.8+ async implementation.
 * @private
 */

/* istanbul ignore next */
var defer = typeof setImmediate === 'function'
  ? setImmediate
  : function(fn){ process.nextTick(fn.bind.apply(fn, arguments)) }

/**
 * Setup session store with the given `options`.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie] Options for cookie
 * @param {Function} [options.genid] // 生成SessionID方式
 * @param {String} [options.name=connect.sid] Session ID cookie name
 * @param {Boolean} [options.proxy]
 * @param {Boolean} [options.resave] Resave unmodified sessions back to the store // 重新保存未修改的Session
 * @param {Boolean} [options.rolling] Enable/disable rolling session expiration
 * @param {Boolean} [options.saveUninitialized] Save uninitialized sessions to the store // 保存未初始化的Session
 * @param {String|Array} [options.secret] Secret for signing session ID
 * @param {Object} [options.store=MemoryStore] Session store
 * @param {String} [options.unset]
 * @return {Function} middleware
 * @public
 */
// options
//  - name
//  - store
//  - cookie
//  - proxy
function session(options){
  var options = options || {}
  //  name - previously "options.key"
    , name = options.name || options.key || 'connect.sid'
    , store = options.store || new MemoryStore
    , cookie = options.cookie || {}
    , trustProxy = options.proxy
    , storeReady = true
    , rollingSessions = options.rolling || false;
  var resaveSession = options.resave;
  var saveUninitializedSession = options.saveUninitialized;
  var secret = options.secret;

  // 生成SessionID的方式
  var generateId = options.genid || generateSessionId;

  if (typeof generateId !== 'function') {
    throw new TypeError('genid option must be a function');
  }

  // 默认resave为true，建议配置resave
  if (resaveSession === undefined) {
    deprecate('undefined resave option; provide resave option');
    resaveSession = true;
  }

  // 默认saveUninitialized为true，建议配置saveUninitialized
  if (saveUninitializedSession === undefined) {
    deprecate('undefined saveUninitialized option; provide saveUninitialized option');
    saveUninitializedSession = true;
  }

  if (options.unset && options.unset !== 'destroy' && options.unset !== 'keep') {
    throw new TypeError('unset option must be "destroy" or "keep"');
  }

  // 下个版本使用destroy
  // TODO: switch to "destroy" on next major
  var unsetDestroy = options.unset === 'destroy';

  // secret 数组或者字符串，如果是数组，包含一个元素
  if (Array.isArray(secret) && secret.length === 0) {
    throw new TypeError('secret option array must contain one or more strings');
  }

  if (secret && !Array.isArray(secret)) {
    secret = [secret];
  }

  // 建议设置secret
  if (!secret) {
    deprecate('req.secret; provide secret option');
  }

  // 正式环境不建议使用MemoryStore
  // notify user that this store is not
  // meant for a production environment
  if ('production' == env && store instanceof MemoryStore) {
    console.warn(warning);
  }

  // 生成一个Session
  // generates the new session
  // 扩展 store generage方法
  store.generate = function(req){
    req.sessionID = generateId(req);
    req.session = new Session(req);
    req.session.cookie = new Cookie(cookie);
  };

  // 检查store有没有实现touch方法
  var storeImplementsTouch = typeof store.touch === 'function';
  store.on('disconnect', function(){ storeReady = false; });
  store.on('connect', function(){ storeReady = true; });

  return function session(req, res, next) {
    // self-awareness
    if (req.session) return next();

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    if (!storeReady) return debug('store is disconnected'), next();

    // pathname mismatch
    var originalPath = parseUrl.original(req).pathname;
    if (0 != originalPath.indexOf(cookie.path || '/')) return next();

    // ensure a secret is available or bail
    if (!secret && !req.secret) {
      next(new Error('secret option required for sessions'));
      return;
    }

    // backwards compatibility for signed cookies
    // req.secret is passed from the cookie parser middleware
    var secrets = secret || [req.secret];

    var originalHash; // 原始hash
    var originalId; // 原始sessionID
    var savedHash; // 保存后的hash

    // expose store
    req.sessionStore = store;

    // get the session ID from the cookie
    // get Session Cookie
    // s:开头
    var cookieId = req.sessionID = getcookie(req, name, secrets);

    // set-cookie
    onHeaders(res, function(){
      if (!req.session) {
        debug('no session');
        return;
      }

      var cookie = req.session.cookie;

      // only send secure cookies via https
      if (cookie.secure && !issecure(req, trustProxy)) {
        debug('not secured');
        return;
      }

      if (!shouldSetCookie(req)) {
        return;
      }

      setcookie(res, name, req.sessionID, secrets[0], cookie.data);
    });

    // proxy end() to commit the session
    var _end = res.end;
    var _write = res.write;
    var ended = false;
    res.end = function end(chunk, encoding) {
      if (ended) {
        return false;
      }

      ended = true;

      var ret;
      var sync = true;

      function writeend() {
        if (sync) {
          ret = _end.call(res, chunk, encoding);
          sync = false;
          return;
        }

        _end.call(res);
      }

      function writetop() {
        if (!sync) {
          return ret;
        }

        if (chunk == null) {
          ret = true;
          return ret;
        }

        var contentLength = Number(res.getHeader('Content-Length'));

        if (!isNaN(contentLength) && contentLength > 0) {
          // measure chunk
          chunk = !Buffer.isBuffer(chunk)
            ? new Buffer(chunk, encoding)
            : chunk;
          encoding = undefined;

          if (chunk.length !== 0) {
            debug('split response');
            ret = _write.call(res, chunk.slice(0, chunk.length - 1));
            chunk = chunk.slice(chunk.length - 1, chunk.length);
            return ret;
          }
        }

        ret = _write.call(res, chunk, encoding);
        sync = false;

        return ret;
      }

      if (shouldDestroy(req)) {
        // destroy session
        debug('destroying');
        store.destroy(req.sessionID, function ondestroy(err) {
          if (err) {
            defer(next, err);
          }

          debug('destroyed');
          writeend();
        });

        return writetop();
      }

      // no session to save
      if (!req.session) {
        debug('no session');
        return _end.call(res, chunk, encoding);
      }

      // touch session
      req.session.touch();

      if (shouldSave(req)) {
        req.session.save(function onsave(err) {
          if (err) {
            defer(next, err);
          }

          writeend();
        });

        return writetop();
      } else if (storeImplementsTouch && shouldTouch(req)) {
        // store implements touch method
        debug('touching');
        store.touch(req.sessionID, req.session, function ontouch(err) {
          if (err) {
            defer(next, err);
          }

          debug('touched');
          writeend();
        });

        return writetop();
      }

      return _end.call(res, chunk, encoding);
    };

    // generate the session
    function generate() {
      store.generate(req);
      originalId = req.sessionID;
      originalHash = hash(req.session); // 数据摘要
      wrapmethods(req.session);
    }

    // 封装一下save方法，在调用save之前先算一下的hash
    // wrap session methods
    function wrapmethods(sess) {
      var _save = sess.save;

      function save() {
        debug('saving %s', this.id);
        savedHash = hash(this);
        _save.apply(this, arguments);
      }

      // 方法直接在一个对象上定义一个新属性，或者修改一个已经存在的属性， 并返回这个对象。
      // https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty
      Object.defineProperty(sess, 'save', {
        configurable: true, // 当且仅当这个属性描述符值为 true 时，该属性可能会改变，也可能会被从相应的对象删除。默认为 false。
        enumerable: false, // 当且仅当该属性出现在相应的对象枚举属性中。默认为 false。
        value: save,
        writable: true
      });
    }

    // check if session has been modified
    // 判断session是否修改过
    function isModified(sess) {
      return originalId !== sess.id || originalHash !== hash(sess);
    }

    // check if session has been saved
    // 判断其是否save过。如果save过，会计算其savedHash
    function isSaved(sess) {
      return originalId === sess.id && savedHash === hash(sess);
    }

    // determine if session should be destroyed
    // 判定session是否被销毁
    function shouldDestroy(req) {
      return req.sessionID && unsetDestroy && req.session == null;
    }

    // determine if session should be saved to store
    // 判定session
    function shouldSave(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      // !保存未初始化的session && cookieId =
      // ?
      return !saveUninitializedSession && cookieId !== req.sessionID
        ? isModified(req.session)
        : !isSaved(req.session)
    }

    // determine if session should be touched
    function shouldTouch(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      return cookieId === req.sessionID && !shouldSave(req);
    }

    // determine if cookie should be set on response
    function shouldSetCookie(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        return false;
      }

      // in case of rolling session, always reset the cookie
      if (rollingSessions) {
        return true;
      }

      return cookieId != req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : req.session.cookie.expires != null && isModified(req.session);
    }

    // generate a session if the browser doesn't send a sessionID
    if (!req.sessionID) {
      debug('no SID sent, generating session');
      generate();
      next();
      return;
    }

    // generate the session object
    debug('fetching %s', req.sessionID);
    store.get(req.sessionID, function(err, sess){
      // error handling
      if (err) {
        debug('error %j', err);

        if (err.code !== 'ENOENT') {
          next(err);
          return;
        }

        generate();
      // no session
      } else if (!sess) {
        debug('no session found');
        generate();
      // populate req.session
      } else {
        debug('session found');
        store.createSession(req, sess);
        originalId = req.sessionID;
        originalHash = hash(sess);

        if (!resaveSession) {
          savedHash = originalHash
        }

        wrapmethods(req.session);
      }

      next();
    });
  };
};

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @private
 */

function generateSessionId(sess) {
  return uid(24);
}

/**
 * Get the session ID cookie from request.
 *
 * @return {string}
 * @private
 */

function getcookie(req, name, secrets) {
  var header = req.headers.cookie;
  var raw;
  var val;

  // read from cookie header
  if (header) {
    var cookies = cookie.parse(header);

    raw = cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        // 验证sessionID
        val = unsigncookie(raw.slice(2), secrets);

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  // back-compat read from cookieParser() signedCookies data
  // 兼容 可以把SessionID放置到signedCookies中？
  if (!val && req.signedCookies) {
    val = req.signedCookies[name];

    if (val) {
      deprecate('cookie should be available in req.headers.cookie');
    }
  }

  // req cookie
  // back-compat read from cookieParser() cookies data
  if (!val && req.cookies) {
    raw = req.cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val) {
          deprecate('cookie should be available in req.headers.cookie');
        }

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  return val;
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * @param {Object} sess
 * @return {String}
 * @private
 */

function hash(sess) {
  return crc(JSON.stringify(sess, function (key, val) {
    if (key !== 'cookie') {
      return val;
    }
  }));
}

/**
 * Determine if request is secure.
 *
 * @param {Object} req
 * @param {Boolean} [trustProxy]
 * @return {Boolean}
 * @private
 */
// 判定请求是否是安全的 like https
function issecure(req, trustProxy) {
  // socket is https server
  if (req.connection && req.connection.encrypted) {
    return true;
  }

  // do not trust proxy
  if (trustProxy === false) {
    return false;
  }

  // no explicit trust; try req.secure from express
  if (trustProxy !== true) {
    var secure = req.secure;
    return typeof secure === 'boolean'
      ? secure
      : false;
  }

  // read the proto from x-forwarded-proto header
  var header = req.headers['x-forwarded-proto'] || '';
  var index = header.indexOf(',');
  var proto = index !== -1
    ? header.substr(0, index).toLowerCase().trim()
    : header.toLowerCase().trim()

  return proto === 'https';
}

/**
 * Set cookie on response.
 *
 * @private
 */

function setcookie(res, name, val, secret, options) {
  // 以s:开头
  var signed = 's:' + signature.sign(val, secret);
  var data = cookie.serialize(name, signed, options);

  debug('set-cookie %s', data);

  // merge cookie
  var prev = res.getHeader('set-cookie') || [];
  var header = Array.isArray(prev) ? prev.concat(data)
    : Array.isArray(data) ? [prev].concat(data)
    : [prev, data];

  res.setHeader('set-cookie', header)
}

/**
 * Verify and decode the given `val` with `secrets`.
 *
 * @param {String} val
 * @param {Array} secrets
 * @returns {String|Boolean}
 * @private
 */
// 验证cookie
function unsigncookie(val, secrets) {
  for (var i = 0; i < secrets.length; i++) {
    var result = signature.unsign(val, secrets[i]);

    if (result !== false) {
      return result;
    }
  }

  return false;
}
