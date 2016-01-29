var express = require('express');
var path = require('path');
// Favicons: those tiny icons in the bookmarks
var favicon = require('serve-favicon');
// Apache style request logging
var logger = require('morgan');
// Handle cookies
var cookieParser = require('cookie-parser');
// Parsing POST requests
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();

var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('data.db');

db.serialize(function() {
  db.each('SELECT * FROM posts', function(err, row) {
    console.log(row.title + ': ' + row.content + ': ' + row.author);
  });
});

db.close();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;