var express = require('express');
var router = express.Router();

var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('data.db');

/* GET home page. */
router.get('/', function(req, res, next) {
  db.all('SELECT * FROM posts', function(err, table) {
//    res.json(table);
    res.render('index', { title: 'Express', posts: table });
//    console.log(row.title + ': ' + row.content + ': ' + row.author);
  });
  db.close();

});

module.exports = router;
