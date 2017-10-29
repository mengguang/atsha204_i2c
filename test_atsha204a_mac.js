var _ = require("lodash");
var util = require("util");
var crypto = require("crypto");

var hex_key = "your atsha204a key here in hex format";
var buffer_key = Buffer.from(hex_key,"hex");

var challenge = Buffer.alloc(32);
challenge.write("Are you OK?");

var opcode = Buffer.alloc(1);
opcode[0] = 0x08;

var mode = Buffer.alloc(1);
mode[0] = 0x00;

var param2 = Buffer.alloc(2);

var otp_0_7 = Buffer.alloc(8);

var otp_8_10 = Buffer.alloc(3);

var sn_8 = Buffer.alloc(1);
sn_8[0] = 0xEE;

var sn_4_7 = Buffer.alloc(4);

var sn_0_1 = Buffer.alloc(2);
sn_0_1[0] = 0x01;
sn_0_1[1] = 0x23;

var sn_2_3 = Buffer.alloc(2);

var data = Buffer.concat([buffer_key , challenge , opcode , mode , param2 , otp_0_7 , otp_8_10 , sn_8 , sn_4_7 , sn_0_1 , sn_2_3]);

console.log(data);
console.log(data.length);

var mac = crypto.createHash('sha256').update(data).digest();
console.log(mac);


