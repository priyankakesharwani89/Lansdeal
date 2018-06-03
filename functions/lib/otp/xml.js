const moment = require('moment');
const js2xml = require('js2xmlparser');

const signer = require('../../utils/signer.js');
const constants = require('../../utils/constants.js');

Object.values = Object.values || (obj => Object.keys(obj).map(key => obj[key]));
Object.isEmpty = Object.isEmpty || (obj => !(obj && Object.keys(obj).length > 0));

const OTP_XMLNS_API1_5 = 'http://www.uidai.gov.in/authentication/otp/1.5';
const OTP_XMLNS_API1_6 = 'http://www.uidai.gov.in/authentication/otp/1.6';

let API_VERSION;
let URL_HOST;
let URL_PATHTEMPLATE;

let OTP_XMLNS;
const OTP_DEFAULT_TID = 'public';
const OTP_TS_ISO8601 = 'YYYY-MM-DDThh:mm:ss';
const TEST_AUA_CODE = 'public';
const TEST_SUBAUA_CODE = TEST_AUA_CODE;
const OTP_AUA_LICENSEKEY = constants.TEST_AUA_LICENSEKEY;
const OTP_DEFAULT_VER = () => API_VERSION;
const OTP_TYPE = {AADHAAR: 'A', MOBILE: 'M'};
const OPTS_CH = {SMS_AND_EMAIL: '00', SMS: '01', EMAIL: '02'};

const OPTS_DEFAULT_CH = OPTS_CH.SMS_AND_EMAIL;

function Otp(Opts, attrs) {
	this['@'] = Object.assign (
		{
			xmlns: OTP_XMLNS,
			uid : attrs.uid,
			tid : attrs.tid ?  attrs.tid : OTP_DEFAULT_TID,
			ts: (moment(attrs.ts, OTP_TS_ISO8601, true).isValid()) ? attrs.ts : moment().format(OTP_TS_ISO8601),
			ac : attrs.ac ?  attrs.ac : TEST_AUA_CODE,
			sa : attrs.sa ? attrs.sa : TEST_SUBAUA_CODE,
			ver : attrs.ver ?  attrs.ver : OTP_DEFAULT_VER(),
			txn: attrs.txn,
			lk: attrs.lk ? attrs.lk : OTP_AUA_LICENSEKEY
		},
		(Object.values(OTP_TYPE).indexOf(attrs.type) > -1) && {type : attrs.type}
	);

	if(Opts) {this.Opts = Opts}
}

function Opts(attrs) {
	if(Object.values(OPTS_CH).indexOf(attrs.ch) > -1) {return;}
	this['@'] = Object.assign(
		{ch: (Object.values(OPTS_CH).indexOf(attrs.ch) > -1) ? attrs.ch : OPTS_DEFAULT_CH}
	)
}

exports.buildXml = function(verConst) {

	init(verConst);

	let TEST_PERSON = constants.TEST_DATA[0];

	let opts = new Opts({ch: OPTS_DEFAULT_CH});
	let otp = new Otp(opts, {uid: TEST_PERSON.uid, tid: OTP_DEFAULT_TID, ac: TEST_AUA_CODE, sa: TEST_SUBAUA_CODE, ver: OTP_DEFAULT_VER(), txn: 'testTxn', lk: OTP_AUA_LICENSEKEY, type: OTP_TYPE.AADHAAR});

	let otpXml = js2xml.parse("Otp", otp/*, {declaration: {include: false}}*/);

	return signer.sign(otpXml);

}

var https = require('http');

exports.testReq = function(uid, reqXml, responseObj) {
	var options = {
		hostname: URL_HOST,
		path: buildUrlPath(uid, URL_PATHTEMPLATE),
		method: 'POST',
		headers: {
			'Content-Type': 'text/plain', // constants.CONTENT_TYPE,
			'Content-Length': Buffer.byteLength(reqXml),
			'REMOTE_ADDR': '127.0.1.1'
		}
	};
	const buffer =	`<?xml version="1.0" encoding="UTF-8"?>
	<OtpRes ret="y" code="252636" txn="AuthDemoClient:public:20170918063026371" ts="2017-09-18T18:30:31.016+05:30" info="02{49951232b1f45f281c7d4f70f3cbbc57c2afd9c0d6bb5f44578bf1304d4868d4,c58ed1f5f5bc043629ae6313e3aa22af12cffe6b87343ebe6048d252e998467d,0180000018000000,1.0,20170918183025,0,0,0,1.6,20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7,public,P,560103,23,E,100,NA,NA,NA,NA,NA,NA,NA,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7}" />`;
	responseObj.set('Content-Type', 'text/xml');
	responseObj.header("Access-Control-Allow-Origin", "*");
	responseObj.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	responseObj.send(parser.toJson(buffer));

	// var req = https.request(options, function(res){
	// 	// console.log(res.statusCode);
	// 	var buffer = '';
	// 	res.on('data', function( data ) {
	// 		buffer = buffer + data;
	// 		// console.log(buffer);
	// 	});
	// 	res.on('end', function( data ) {
	// 		console.log('\nResponse: ');
	// 		console.log( buffer );
	// 		responseObj.set('Content-Type', 'text/xml');
	// 		responseObj.header("Access-Control-Allow-Origin", "*");
	// 		responseObj.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	// 		responseObj.send(parser.toJson(buffer));
	// 	});
	// });

	// req.on('error',function(err){
	// 	console.log(err.message);
	// });

	// console.log('\nURL: ');
	// console.log(URL_HOST + buildUrlPath(uid, URL_PATHTEMPLATE));

	// // reqXml = reqXml.replace(/\s*Id="_0"/,'').replace(/#_0/,'');
	// console.log('\nSending XML: ');
	// console.log(reqXml);
	// req.write(reqXml);
	// req.end();
}

function buildUrlPath(uid, pathTemplate) {
	let ver = API_VERSION;
	let ac = constants.TEST_AUTH_CODE;
	let uid0 = uid[0];
	let uid1 = uid[1];
	let asalk = constants.TEST_ASA_LICENSEKEY;

	let path = pathTemplate.replace('<ver>', ver)
	.replace('<ac>', ac)
	.replace('<uid[0]>', uid0)
	.replace('<uid[1]>', uid1)
	.replace('<asalk>', asalk)

	return path;
}

function init(verConst) {
	API_VERSION = verConst.API_VERSION;
	URL_HOST = verConst.URL_OTP_HOST;
	URL_PATHTEMPLATE = verConst.URL_OTP_PATHTEMPLATE;
	switch(API_VERSION) {
		case constants.OTP.API1_5.API_VERSION:
		OTP_XMLNS = OTP_XMLNS_API1_5;
		break;
		case constants.OTP.API1_6.API_VERSION:
		OTP_XMLNS = OTP_XMLNS_API1_6;
		break;
	}
}

//buildXml(constants.OTP.API1_5);
