const { createHmac } = require('crypto');

const dbcMask =   [0x7f ,0xff ,0xff ,0xff];
const shiftArr =  [24   ,16   ,8    ,0];
/**
 * Creates and returns the dynamic array value used in calculating the OTP.
 * @param {String} hashedValue Response from HMAC-SHA1 function, 20 bytes.
 * @returns 
 */
function truncate(hashedValue) {
  // Split into byte pairs
  const bytes = hashedValue.match(/.{2}/g);
  // Grab the offset value, somewhere between 0 and 15, inclusive.
  const offset = (Number('0x' + bytes.slice(-1)[0]) & 0xf);
  
  return bytes
    // Get dynamic array
    .slice(offset, offset + 4)
    // Convert to numbers and mask off 7f ff ff ff
    .map((val, idx) => Number('0x' + val) & (dbcMask[idx]))
    // Return the dynamic array as a number
    .reduce((acc, cur, idx) => acc |= cur << shiftArr[idx], 0);
}
/**
 * RFC 4226 HMAC-based One Time Password
 * @param {String} key 
 * @param {Number} counter 
 * @param {Number} length 
 * @returns 
 */
function hotp(key, counter, length) {
  counter = counter || 0;
  length  = length || 6;

  const counterBuffer = Buffer.allocUnsafe(8);
  // Right aligned? Matches the test values in RFC4226
  counterBuffer.writeUInt32BE(counter, 4);
  const mac = createHmac('sha1', key).update(counterBuffer).digest('hex');
  const macValue = truncate(mac);
  // Return last `length`
  return (macValue).toString().slice(-length).padStart(length, '0');
}
/**
 * RFC 6238 Time-based One Time Password
 * @param {*} key for the HMAC function 
 * @param {*} utar Unix Time at Request - the time the request was made, in 
 * seconds. JS will return milliseconds.
 * @param {*} step How large the X step is
 * @param {*} length length of key to return
 * @returns 
 */
function totp(key, utar, step, length) {
  // 30 second steps by default
  step = step || 30;
  const cut = Date.now() / 1000;
  const counter = Math.floor((cut - utar) / step);
  
  return hotp(key, counter, length);
}
/**
 * Validates an OTP code given the arguments
 * @param {String} otpValue The OTP value 
 * @param {String} key 
 * @param {Number} counter
 * @param {Number} lookahead How many counts should be looked at ahead of 
 * `counter`.
 * @param {Number} lookbehind How many counts should be looked at behind 
 * `counter`.
 * @returns boolean if the `otpValue` can be verified by the arguments given
 */
function validateHotp(otpValue, key, counter, lookahead, lookbehind) {
  lookahead = lookahead || 5;
  lookbehind = lookbehind || 1;

  const length = otpValue.length;
  const lookaround = [counter];

  for (; lookbehind > 0; lookbehind--) {
    if (counter - lookbehind < 0) continue;
    lookaround.push(counter - lookbehind);
  }
  for (; lookahead > 0; lookaround.push((counter + lookahead--)));
  // You don't have to evaluate the entire search area but I did
  return lookaround
    .map(val => hotp(key, val, length))
    .some(val => val == otpValue);
}
/**
 * 
 * @param {String} otpValue 
 * @param {String} key 
 * @param {Number} utar 
 * @param {Number} step 
 * @param {Number} lookahead 
 * @param {Number} lookbehind 
 * @returns 
 */
function validateTotp(otpValue, key, utar, step, lookahead, lookbehind) {
  // 30 second steps by default
  step = step || 30;

  const cut = Date.now() / 1000;
  const counter = Math.floor((cut - utar) / step);

  return validateHotp(otpValue, key, counter, lookahead, lookbehind);
}

module.exports = {
  hotp,
  totp,
  validateHotp,
  validateTotp
};
