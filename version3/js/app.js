const CTX = require("./index").CTX;

function stringtobytes(s) {
    var b = [];
    for (var i = 0; i < s.length; i++) {
        b.push(s.charCodeAt(i));
    }
    return b;
}

let ctx = new CTX("NIST256");

let CS = [];
let DS = [];
let publicKey = [];
let privateKey = [];
let plaintext = "Das ist ein test";
let message = stringtobytes(plaintext);
console.log("message:");
console.log(message);
console.log(ctx.ECDH.asciitobytes(plaintext));
console.log(ctx.ECDH.stringtobytes(plaintext));

let rng = new ctx.RAND();
rng.clean();

let RAW = [];

for(let i = 0; i < 100; i++) RAW[i] = 0;
rng.seed(100,RAW);

let sha = ctx.ECP.HASH_TYPE;
let res = -1;

ctx.ECDH.KEY_PAIR_GENERATE(rng, privateKey, publicKey);


while(res !== 0) {
	res = ctx.ECDH.ECPSP_DSA(sha, rng, privateKey, message, CS, DS);
}
console.log("res:");
console.log(res);
console.log("CS (r): 0x" + ctx.ECDH.bytestostring(CS));
console.log(CS);
console.log("DS (s): 0x" + ctx.ECDH.bytestostring(DS));
console.log(DS);

if(ctx.ECDH.ECPVP_DSA(sha, publicKey, message, CS, DS)) console.log("signature is not valid!");
else console.log("signature verified!");

