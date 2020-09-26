var http = require("http");
var util =  require("util");
const zwsp_steg = require('zwsp-steg');

var options = {
  host: "web.chal.csaw.io",
  port: 5018,
  path: "/ahsdiufghawuflkaekdhjfaldshjfvbalerhjwfvblasdnjfbldf/alm0st_2_3z"
};

const src = http.get(options, function(res){
  let data ='';
  res.setEncoding('utf8');
  res.on('data', function(chunk){
    data += chunk;
  });
  res.on('end', function(){
    console.log(data.toString('ascii'));
    let decoded = zwsp_steg.decode(data.toString('ascii'));
    console.log(decoded);
    
  });
});


