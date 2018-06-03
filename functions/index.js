const constants = require('./utils/constants.js');
const functions = require('firebase-functions');
const xmlAuth = require('./lib/auth/xml.js');
const xmlOTP = require('./lib/otp/xml.js');
const fs = require('fs');
const parser = require('xml2json');

var base64 = require('file-base64');


exports.sendOtp = functions.https.onRequest((request, response) => {
  const buffer = `<?xml version="1.0" encoding="UTF-8"?>
	<OtpRes ret="y" code="252636" txn="AuthDemoClient:public:20170918063026371" ts="2017-09-18T18:30:31.016+05:30" info="02{49951232b1f45f281c7d4f70f3cbbc57c2afd9c0d6bb5f44578bf1304d4868d4,c58ed1f5f5bc043629ae6313e3aa22af12cffe6b87343ebe6048d252e998467d,0180000018000000,1.0,20170918183025,0,0,0,1.6,20ef0f0c8d0eea98772412cea9b3b92612e3e53cb5e59152b5703165f56e8a53,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7,public,P,560103,23,E,100,NA,NA,NA,NA,NA,NA,NA,efa1f375d76194fa51a3556a97e641e61685f914d446979da50a551a4333ffd7}" />`;
  console.log('Response OTP:', parser.toJson(buffer));
  response.header("Access-Control-Allow-Origin", "*");
  response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  response.json(parser.toJson(buffer));
  //   xmlOTP.buildXml(constants.AUTH.API2_0).then((sign) => {
  //     xmlOTP.testReq(constants.TEST_DATA[0].uid, sign, response)
  //  });
});

exports.auth = functions.https.onRequest((request, response) => {
  xmlAuth.buildXml(constants.AUTH.API2_0).then((sign) => {
    xmlAuth.testReq(constants.TEST_DATA[0].uid, sign, response)
  });
});


exports.ekyc = functions.https.onRequest((request, response) => {
  base64.encode('./res/marc.jpg', function (err, base64String) {
    const buffer = `<?xml version="1.0" encoding="UTF-8"?>
    <Resp status="0" ko="ASA" ret="y" code="" txn="" ts="" err="">
    <KycRes ret="y" code="" txn="" ts="" ttl="" actn="" err="">
  <Rar>base64 encoded fully valid Auth response XML for resident</Rar>
  <UidData uid="999999990057">
  <Poi name="Rohit Pandey" dob="08-07-1985" gender="M" />
  <Poa co="" house="603/4 Vindyachal" street="7TH Road Raja Wadi" lm="" loc="Neelkanth Valley" vtc="Mumbai"
  subdist="" dist="Mumbai" state="Maharashrta" country="" pc="243001" po="Ghatkopar (EAST)"/>
  <LData lang="" name="" co="" house="" street="" lm="" loc="" vtc=""
  subdist="" dist="" state="" country="" pc="" po=""/>
  <Pht>` + base64String + `</Pht>
  <Prn type="pdf">` + base64String + `</Prn>
  </UidData>
  <Signature/>
  </KycRes>
    </Resp>`;
    console.log('Response OTP:', parser.toJson(buffer));
    response.header("Access-Control-Allow-Origin", "*");
    response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    response.json(parser.toJson(buffer));
    //   xmlOTP.buildXml(constants.AUTH.API2_0).then((sign) => {
    //     xmlOTP.testReq(constants.TEST_DATA[0].uid, sign, response)
    //  });
  });

  exports.eSign= functions.https.onRequest((request, response) => {
    response.header("Access-Control-Allow-Origin", "*");
    response.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
   
    response.json({
      "id": request.body.documentId,
      "is_agreement": true,
      "agreement_type": "outbound",
      "agreement_status": "requested",
      "file_name": request.body.documentId,
      "created_at": "2017-07-17 21:09:59",
      "self_signed": false,
      "self_sign_type": "aadhaar",
      "no_of_pages": 1,
      "signing_parties": [
          {
              "name": request.body.email || request.body,mobile,
              "identifier": request.body.email || request.body,mobile,
              "status": "requested",
              "type": "self",
              "signature_type": "aadhaar",
              "reason": "Property document "
          }
      ],
      "sign_request_details": {
          "name": "Lansdeal",
          "identifier": "info@lansdeal.com",
          "requested_on": new Date().toDateString(),
          "expire_on": new Date().toDateString(),
          "requester_type": "org"
      },
      "channel": "api"
  }
  )
  });
});
