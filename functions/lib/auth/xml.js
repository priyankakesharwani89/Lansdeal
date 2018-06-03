const moment = require('moment');
const js2xml = require('js2xmlparser');
const parser = require('xml2json');

const encryptor = require('./encryptor.js');
const signer = require('../../utils/signer.js');
const constants = require('../../utils/constants.js');
//Function to get all values in an object
Object.values = Object.values || (obj => Object.keys(obj).map(key => obj[key]));
Object.isEmpty = Object.isEmpty || (obj => !(obj && Object.keys(obj).length > 0));

const AUTH_XMLNS_API2_0 = 'http://www.uidai.gov.in/authentication/uid-auth-request/2.0';
const PID_XMLNS_API2_0 = 'http://www.uidai.gov.in/authentication/uid-auth-request-data/2.0';
const AUTH_XMLNS_API1_6 = 'http://www.uidai.gov.in/authentication/uid-auth-request/1.6';
const PID_XMLNS_API1_6 = 'http://www.uidai.gov.in/authentication/uid-auth-request-data/1.6';

const AUTH_DEFAULT_TID_API1_6 = 'public';
const AUTH_DEFAULT_TID_API2_0 = '';

const PID_DEFAULT_VER_API1_6 = '1.0';
const PID_DEFAULT_VER_API2_0 = '2.0';

let API_VERSION;
let URL_HOST;
let URL_PATHTEMPLATE;

//AUTH
let AUTH_XMLNS;
let PID_XMLNS;
const AUTH_DEFAULT_RC = 'Y';
let AUTH_DEFAULT_TID;
const AUTH_AUA_CODE = constants.TEST_AUTH_CODE;
const AUTH_SUBAUA_CODE = constants.TEST_SUBAUA_CODE;
const AUTH_DEFAULT_VER = () => API_VERSION;
const AUTH_AUA_LICENSEKEY = constants.TEST_AUA_LICENSEKEY;
//USES
const USES_PI = {
	YES: 'y',
	NO: 'n'
};
const USES_PA = {
	YES: 'y',
	NO: 'n'
};
const USES_PFA = {
	YES: 'y',
	NO: 'n'
};
const USES_BIO = {
	YES: 'y',
	NO: 'n'
};
const USES_BT = {
	FINGER_MINUTIAE: 'FMR',
	FINGER_IMAGE: 'FIR',
	IRIS_IMAGE: 'IIR',
	FACE_IMAGE_DATA: 'FID'
};
const USES_PIN = {
	YES: 'y',
	NO: 'n'
};
const USES_OTP = {
	YES: 'y',
	NO: 'n'
};

const USES_DEFAULT_PI = USES_PI.YES;
const USES_DEFAULT_PA = USES_PA.NO;
const USES_DEFAULT_PFA = USES_PFA.NO;
const USES_DEFAULT_BIO = USES_BIO.NO;
const USES_DEFAULT_PIN = USES_PIN.NO;
const USES_DEFAULT_OTP = USES_OTP.NO;
//META
const META_DEFAULT_UDC = 'UIDAI:SampleClient';
//SKEY
const CERT_EXPRY_FORMAT = 'YYYYMMDD';
const TEST_CERT_CI = () => encryptor.getExpiry();
const DATE_FORMAT_UNIX = 'x';
//DATA
const DATA_TYPE = {
	XML: 'X',
	PROTOBUF: 'P'
};
const DATA_DEFAULT_TYPE = DATA_TYPE.XML;
//PID
let PID_DEFAULT_VER;
const PID_TS_ISO8601 = 'YYYY-MM-DDThh:mm:ss';
//DEMO
const LANGUAGE_CODE = {
	Assamese: '01',
	Bengali: '02',
	Gujarati: '05',
	Hindi: '06',
	Kannada: '07',
	Malayalam: '11',
	Manipuri: '12',
	Marathi: '13',
	Oriya: '15',
	Punjabi: '16',
	Tamil: '20',
	Telugu: '21',
	Urdu: '22'
}
//PI
const PI_MATCHING_STGY = {
	EXACT: 'E',
	PARTIAL: 'P'
};
const PI_MATCH_VALUE = [...Array(100).keys()].map(x => ++x);
const PI_LMATCH_VALUE = [...Array(100).keys()].map(x => ++x);
const PI_GENDER = {
	MALE: 'M',
	FEMALE: 'F',
	TRANSGENDER: 'T'
}
const PI_DOB_FORMAT = 'YYYY-MM-DD';
const PI_DOB_YEAR_FORMAT = 'YYYY';
const PI_DOB_TYPE = {
	VERIFIED: 'V',
	DECLARED: 'D',
	APPROXIMATE: 'A'
};

const PI_DEFAULT_MTCH_STGY = PI_MATCHING_STGY.EXACT;
const PI_DEFAULT_MATCH_VALUE = 100;
//Not specified in specs
const PI_DEFAULT_LMATCH_VALUE = 100;
//PA
const PA_MATCHING_STGY = {
	EXACT: 'E'
};
const PA_DEFAULT_MTCH_STGY = PA_MATCHING_STGY.EXACT;
//PFA
const PFA_MATCHING_STGY = {
	EXACT: 'E',
	PARTIAL: 'P'
};
const PFA_MATCH_VALUE = [...Array(100).keys()].map(x => ++x);
const PFA_LMATCH_VALUE = [...Array(100).keys()].map(x => ++x);

const PFA_DEFAULT_MTCH_STGY = PFA_MATCHING_STGY.EXACT;
const PFA_DEFAULT_MATCH_VALUE = 100;
//Not specified in specs
const PFA_DEFAULT_LMATCH_VALUE = 100;
//BIO
const BIO_TYPE = {
	FINGER_MINUTIAE: 'FMR',
	FINGER_IMAGE: 'FIR',
	IRIS_IMAGE: 'IIR',
	FACE_IMAGE_DATA: 'FID'
};
const BIO_POSH = {
	LEFT_IRIS: 'LEFT_IRIS',
	RIGHT_IRIS: 'RIGHT_IRIS',
	LEFT_INDEX: 'LEFT_INDEX',
	LEFT_LITTLE: 'LEFT_LITTLE',
	LEFT_MIDDLE: 'LEFT_MIDDLE',
	LEFT_RING: 'LEFT_RING',
	LEFT_THUMB: 'LEFT_THUMB',
	RIGHT_INDEX: 'RIGHT_INDEX',
	RIGHT_LITTLE: 'RIGHT_LITTLE',
	RIGHT_MIDDLE: 'RIGHT_MIDDLE',
	RIGHT_RING: 'RIGHT_RING',
	RIGHT_THUMB: 'RIGHT_THUMB',
	FACE: 'FACE',
	UNKNOWN: 'UNKNOWN'
};
//PV
let IS_UIDAI = false;

let pidXml;

function Auth(Uses, Meta, Skey, Data, Hmac, attrs) {
	this['@'] = Object.assign({
			// xmlns: AUTH_XMLNS,
			uid: attrs.uid,
			tid: attrs.tid ? attrs.tid : AUTH_DEFAULT_TID,
			ac: attrs.ac ? attrs.ac : AUTH_AUA_CODE,
			sa: attrs.sa ? attrs.sa : AUTH_SUBAUA_CODE,
			ver: attrs.ver ? attrs.ver : AUTH_DEFAULT_VER(),
			txn: attrs.txn,
			lk: attrs.lk ? attrs.lk : AUTH_AUA_LICENSEKEY
		},
		(API_VERSION == constants.AUTH.API2_0.API_VERSION) && {
			rc: attrs.rc ? attrs.rc : AUTH_DEFAULT_RC
		}
	);
	this.Uses = Uses;
	this.Meta = Meta;
	this.Skey = Skey;
	this.Data = Data;
	this.Hmac = Hmac;
}

function Uses(attrs) {
	this['@'] = Object.assign({
			pi: (Object.values(USES_PI).indexOf(attrs.pi) > -1) ? attrs.pi : USES_DEFAULT_PI,
			pa: (Object.values(USES_PA).indexOf(attrs.pa) > -1) ? attrs.pa : USES_DEFAULT_PA,
			pfa: (Object.values(USES_PFA).indexOf(attrs.pfa) > -1) ? attrs.pfa : USES_DEFAULT_PFA,
			bio: (Object.values(USES_BIO).indexOf(attrs.bio) > -1) ? attrs.bio : USES_DEFAULT_BIO,
			pin: (Object.values(USES_PIN).indexOf(attrs.pin) > -1) ? attrs.pin : USES_DEFAULT_PIN,
			otp: (Object.values(USES_OTP).indexOf(attrs.otp) > -1) ? attrs.otp : USES_DEFAULT_OTP
		},
		//TODO if make bt mandatory if bio = y
		((attrs.bio === USES_BIO.YES) && (Object.values(USES_BT).indexOf(attrs.bt) > -1)) && {
			bt: attrs.bt
		}
	);
}

function Meta(attrs) {
	this['@'] = Object.assign({
			udc: attrs.udc ? attrs.udc : META_DEFAULT_UDC
		},
		//TODO do bioauth check
		(API_VERSION == constants.AUTH.API1_6.API_VERSION) && {
			fdc: "NC",
			idc: "NA",
			lot: "P",
			lov: "560103",
			pip: "127.0.0.1"
		},
		(attrs.rdsId && attrs.rdsVer &&
			attrs.dpId && attrs.dc &&
			attrs.mi && attrs.mc) && {
			rdsId: attrs.rdsId,
			rdsVer: attrs.rdsVer,
			dpId: attrs.dpId,
			dc: attrs.dc,
			mi: attrs.mi,
			mc: attrs.mc
		}
	);
}

function Skey(encEncrySKey, attrs) {
	this['@'] = {
		ci: (moment(attrs.ci, CERT_EXPRY_FORMAT, true).isValid()) ? attrs.ci : TEST_CERT_CI()
	};
	this['#'] = encEncrySKey;
}

function Data(data, attrs) {
	this['@'] = {
		type: (Object.values(DATA_TYPE).indexOf(attrs.type) > -1) ? attrs.type : DATA_DEFAULT_TYPE
	};
	this['#'] = data;
}

function Hmac(hmac) {
	this['#'] = hmac;
}

function Pid(Demo, Bios, Pv, attrs) {
	this['@'] = Object.assign({
			"xmlns:ns2": PID_XMLNS
		}, {
			ts: (moment(attrs.ts, PID_TS_ISO8601, true).isValid()) ? attrs.ts : moment().format(PID_TS_ISO8601),
			ver: attrs.ver ? attrs.ver : PID_DEFAULT_VER
		},
		false && {
			wadh: attrs.wadh
		}
	);
	if (Demo || !Object.isEmpty(Demo)) {
		this.Demo = Demo
	};
	if (Bios || !Object.isEmpty(Bios)) {
		this.Bios = Bios
	};
	if (Pv || !Object.isEmpty(Pv)) {
		this.Pv = Pv
	};
}

function Demo(Pi, Pa, Pfa, attrs) {
	this['@'] = Object.assign({},
		(attrs && Object.values(LANGUAGE_CODE).indexOf(attrs.lang) > -1) && {
			lang: attrs.lang
		}
	);
	if (Pi || !Object.isEmpty(Pi)) {
		this.Pi = Pi
	};
	if (Pa || !Object.isEmpty(Pa)) {
		this.Pa = Pa
	};
	if (Pfa || !Object.isEmpty(Pfa)) {
		this.Pfa = Pfa
	};
}

function Pi(attrs) {
	this['@'] = Object.assign(
		(attrs.name) && {
			ms: (Object.values(PI_MATCHING_STGY).indexOf(attrs.ms) > -1) ? attrs.ms : PI_DEFAULT_MTCH_STGY,
			mv: (Object.values(PI_MATCH_VALUE).indexOf(attrs.mv) > -1) ? attrs.mv : PI_DEFAULT_MATCH_VALUE,
			name: attrs.name
		},
		//TODO add lang check
		(attrs.lname) && {
			lname: attrs.lname,
			lmv: (Object.values(PI_LMATCH_VALUE).indexOf(attrs.lmv) > -1) ? attrs.lmv : PI_DEFAULT_LMATCH_VALUE
		},
		(Object.values(PI_GENDER).indexOf(attrs.gender) > -1) && {
			gender: attrs.gender
		},
		(moment(attrs.dob, PI_DOB_FORMAT, true).isValid() || moment(attrs.dob, PI_DOB_YEAR_FORMAT, true).isValid()) && {
			dob: attrs.dob
		},
		(Object.values(PI_DOB_TYPE).indexOf(attrs.dobt) > -1) && {
			dobt: attrs.dobt
		},
		(attrs.age) && {
			age: attrs.age
		},
		(attrs.phone) && {
			phone: attrs.phone
		},
		(attrs.email) && {
			email: attrs.email
		}
	)
}

function Pa(attrs) {
	this['@'] = Object.assign(
		(attrs.co || attrs.house ||
			attrs.street || attrs.lm ||
			attrs.loc || attrs.vtc ||
			attrs.subdist || attrs.dist ||
			attrs.state || attrs.country ||
			attrs.pc || attrs.po) &&
		{
			ms: (Object.values(PA_MATCHING_STGY).indexOf(attrs.ms) > -1) ? attrs.ms : PA_DEFAULT_MTCH_STGY
		},
		(attrs.co) && {
			co: attrs.co
		},
		(attrs.house) && {
			house: attrs.house
		},
		(attrs.street) && {
			street: attrs.street
		},
		(attrs.lm) && {
			lm: attrs.lm
		},
		(attrs.loc) && {
			loc: attrs.loc
		},
		(attrs.vtc) && {
			vtc: attrs.vtc
		},
		(attrs.subdist) && {
			subdist: attrs.subdist
		},
		(attrs.dist) && {
			dist: attrs.dist
		},
		(attrs.state) && {
			state: attrs.state
		},
		(attrs.country) && {
			country: attrs.country
		},
		(attrs.pc) && {
			pc: attrs.pc
		},
		(attrs.po) && {
			po: attrs.po
		}
	);
}

function Pfa(attrs) {
	this['@'] = Object.assign(
		(attrs.av) && {
			ms: (Object.values(PFA_MATCHING_STGY).indexOf(attrs.ms) > -1) ? attrs.ms : PFA_DEFAULT_MTCH_STGY,
			mv: (Object.values(PFA_MATCH_VALUE).indexOf(attrs.mv) > -1) ? attrs.mv : PFA_DEFAULT_MATCH_VALUE,
			av: attrs.av
		},
		//TODO add lang check
		(attrs.lav) && {
			lav: attrs.lav,
			lmv: (Object.values(PFA_LMATCH_VALUE).indexOf(attrs.lmv) > -1) ? attrs.lmv : PFA_DEFAULT_LMATCH_VALUE
		}
	)
}

function Bios(attrs, bio) {
	if (Object.values(BIO_TYPE).indexOf(attrs.type) < 0 ||
		Object.values(BIO_POSH).indexOf(attrs.posh) < 0 ||
		!attrs.bs || attrs.bio) {
		return;
	}

	this['@'] = {
		dih: attrs.dih
	};
	this.Bio = {
		'@': {
			type: attrs.type,
			posh: attrs.posh,
			bs: attrs.bs
		},
		'#': bio
	}
}

function Pv(attrs) {

	if ((IS_UIDAI && !attrs.otp && !attrs.pin) || (!IS_UIDAI && !attrs.otp)) {
		return;
	}
	this['@'] = Object.assign({
			otp: attrs.otp
		},
		isUIDAI && {
			pin: attrs.pin
		}
	)

}

function init(verConst) {
	API_VERSION = verConst.API_VERSION;
	URL_PATHTEMPLATE = verConst.URL_AUTH_PATHTEMPLATE;
	URL_HOST = verConst.URL_AUTH_HOST;
	switch (API_VERSION) {
		case constants.AUTH.API1_6.API_VERSION:
			AUTH_XMLNS = AUTH_XMLNS_API1_6;
			PID_XMLNS = PID_XMLNS_API1_6;
			AUTH_DEFAULT_TID = AUTH_DEFAULT_TID_API1_6;
			PID_DEFAULT_VER = PID_DEFAULT_VER_API1_6;
			break;
		case constants.AUTH.API2_0.API_VERSION:
			AUTH_XMLNS = AUTH_XMLNS_API2_0;
			PID_XMLNS = PID_XMLNS_API2_0;
			AUTH_DEFAULT_TID = AUTH_DEFAULT_TID_API2_0;
			PID_DEFAULT_VER = PID_DEFAULT_VER_API2_0;
			break;
	}

	encryptor.init(verConst);
}

let fs = require('fs');
exports.buildXml = function (verConst) {

	init(verConst);

	let empty;

	let TEST_PERSON = constants.TEST_DATA[0];


	let uses = new Uses({
		pi: USES_DEFAULT_PI,
		pa: USES_DEFAULT_PA,
		pfa: USES_DEFAULT_PFA,
		bio: USES_DEFAULT_BIO,
		pin: USES_DEFAULT_PIN,
		otp: USES_DEFAULT_OTP
	});
	let meta = new Meta({
		udc: META_DEFAULT_UDC
	});

	let ci = moment(encryptor.getExpiry(), DATE_FORMAT_UNIX).format(CERT_EXPRY_FORMAT);
	let sKey = encryptor.getSessionKey();
	let encrySKey = encryptor.encryptUsingPublicKey(sKey.toString('binary'));
	let encEncrySKey = encryptor.encode64(encrySKey);
	let skey = new Skey(encEncrySKey, {
		ci: ci
	});


	let pi = new Pi({
		ms: PI_DEFAULT_MTCH_STGY,
		mv: PI_DEFAULT_MATCH_VALUE,
		name: TEST_PERSON.name /*, gender: TEST_PERSON.gender, dob: TEST_PERSON.dob, dobt: TEST_PERSON.dobt, phone: TEST_PERSON.phone, email: TEST_PERSON.email*/
	});
	// let pa = new Pa({ms: PA_DEFAULT_MTCH_STGY, street: TEST_PERSON.street, vtc: TEST_PERSON.vtc, subdist: TEST_PERSON.subdist, dist: TEST_PERSON.district, state: TEST_PERSON.state, pc: TEST_PERSON.pincode})

	let demo = new Demo(pi);

	let ts = moment().subtract(1, 'hour').format(PID_TS_ISO8601);
	let ver = PID_DEFAULT_VER;
	let pid = new Pid(demo, empty, empty, {
		ts: ts,
		ver: ver
	});

	let pidXml = js2xml.parse("ns2:Pid", pid /* , {declaration: {include: false}}*/ );
	console.log("PID:\n" + pidXml)

	let encryPidXml = encryptor.encryptUsingSessionKey(pidXml, ts, sKey, true);
	let encEncryPidXml = encryptor.encode64(encryPidXml)
	let data = new Data(encEncryPidXml, {
		type: DATA_DEFAULT_TYPE
	});

	let pidXmlHash = encryptor.generateSha256Hash(pidXml);
	let encryPidXmlHash = encryptor.encryptUsingSessionKey(pidXmlHash, ts, sKey);
	let encEncryPidXmlHash = encryptor.encode64(encryPidXmlHash);
	let hmac = new Hmac(encEncryPidXmlHash);

	let auth = new Auth(uses, meta, skey, data, hmac, {
		uid: TEST_PERSON.uid,
		rc: AUTH_DEFAULT_RC,
		tid: AUTH_DEFAULT_TID,
		ac: AUTH_AUA_CODE,
		sa: AUTH_SUBAUA_CODE,
		ver: AUTH_DEFAULT_VER(),
		txn: 'testTxn',
		lk: AUTH_AUA_LICENSEKEY
	});

	let authXml = js2xml.parse("Auth", auth /*, {declaration: {include: false}}*/ );
	// console.log("AUTH: \n" + authXml);

	return signer.sign(authXml);
}

//// These are the option defaults These
var optionsJSON = {
	mergeCDATA: true,	// extract cdata and merge with text nodes
	grokAttr: true,		// convert truthy attributes to boolean, etc
	grokText: true,		// convert truthy text/attr to boolean, etc
	normalize: true,	// collapse multiple spaces to single space
	xmlns: true, 		// include namespaces as attributes in output
	namespaceKey: '_ns', 	// tag name for namespace objects
	textKey: '_text', 	// tag name for text nodes
	valueKey: '_value', 	// tag name for attribute values
	attrKey: '_attr', 	// tag for attr groups
	cdataKey: '_cdata',	// tag for cdata nodes (ignored if mergeCDATA is true)
	attrsAsObject: true, 	// if false, key is used as prefix to name, set prefix to '' to merge children and attrs.
	stripAttrPrefix: true, 	// remove namespace prefixes from attributes
	stripElemPrefix: true, 	// for elements of same name in diff namespaces, you can enable namespaces and access the nskey property
	childrenAsArray: true 	// force children into arrays
};

// you can change the defaults by passing the parser an options object of your own
var myOptions = {
	mergeCDATA: false,
	xmlns: false,
	attrsAsObject: false
}

var https = require('http');
exports.testReq = function (uid, reqXml, responseObj) {
	var options = {
		hostname: URL_HOST,
		path: buildUrlPath(uid, URL_PATHTEMPLATE),
		method: 'POST',
		headers: {
			'Content-Type': constants.CONTENT_TYPE,
			'Content-Length': Buffer.byteLength(reqXml),
			'REMOTE_ADDR': '127.0.1.1'
		}
	};

	var req = https.request(options, function (res) {
		// console.log(res.statusCode);
		var buffer = '';
		res.on('data', function (data) {
			buffer = buffer + data;

			// console.log(buffer);
		});
		res.on('end', function (data) {
			console.log('\nResponse: ');
			console.log(buffer);
			responseObj.set('Content-Type', 'text/xml');
			responseObj.header("Access-Control-Allow-Origin", "*");
			responseObj.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
			responseObj.send(parser.toJson(`<?xml version="1.0" encoding="UTF-8"?><AuthRes code="3726201da3f742d9b00682d92e72e5a6" info="02{49951232b1f45f281c7d4f70f3cbbc57c2afd9c0d6bb5f44578bf1304d4868d4,c58ed1f5f5bc043629ae6313e3aa22af12cffe6b87343ebe6048d252e998467d,0180000018000000,1.0,20170918183025,0,0,0,1.6,20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7,public,P,560103,23,E,100,NA,NA,NA,NA,NA,NA,NA,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7}" ret="y" ts="2017-09-18T18:30:31.016+05:30" txn="AuthDemoClient:public:20170918063026371"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>5R5vsHpDWYda8aV7987RAcW6WP52VdQLQCoRERyOOm4=</DigestValue></Reference></SignedInfo><SignatureValue>XGyK1x5Se9ZntfAvQ/TW5J9+7FANkImDFY9O1F7WBLU438RU7tUrulsHgxYfo8OX7YtlRp2ekaXg
			TsDzG5e2AVGKiFsTuIT9/O3YZc4ti0glE7CFBuIM8Lk5FLo/Fk3oGjWgghn++78kh+RUunadhM6S
			YPfA/vCIw19p/F1HA7aSQr5F3+Www0Wobg6xj+kOfFv6zw8v38cadbiaBrDoXl7Tt6cx+pmSnsQV
			F/qowKOt9zkYeUXk1RLcaLUEMUL3q84pWNlapZ9uh4Wwtcn0QASUhkufR1vdFB7NWQ984KMHrLQr
			w8ddKhHAwn8DEj1pWlj050BXQwFdF9Rh+63v9w==</SignatureValue></Signature></AuthRes>
			`));
		});
	});

	req.on('error', function (err) {
		console.log('error from uidai auth:',err.message);
	});

	console.log('\nURL: ');
	console.log(URL_HOST + buildUrlPath(uid, URL_PATHTEMPLATE));

	// reqXml = fs.readFileSync(require('path').join(__dirname, '..', '..', 'res', 'example_request_auth1_6.xml'),'utf8');
	console.log('\nSending XML: ');
	console.log(reqXml);
	req.write(reqXml);
	req.end();
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
