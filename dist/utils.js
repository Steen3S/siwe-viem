"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseIntegerNumber = exports.isEIP55Address = exports.checkInvalidKeys = exports.isValidISO8601Date = exports.generateNonce = void 0;
const random_1 = require("@stablelib/random");
const sha3_1 = require("@noble/hashes/sha3");
const utils_1 = require("@noble/hashes/utils");
const ISO8601 = /^(?<date>[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]))[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
/**
 * This method leverages a native CSPRNG with support for both browser and Node.js
 * environments in order generate a cryptographically secure nonce for use in the
 * SiweMessage in order to prevent replay attacks.
 *
 * 96 bits has been chosen as a number to sufficiently balance size and security considerations
 * relative to the lifespan of it's usage.
 *
 * @returns cryptographically generated random nonce with 96 bits of entropy encoded with
 * an alphanumeric character set.
 */
const generateNonce = () => {
    const nonce = (0, random_1.randomStringForEntropy)(96);
    if (!nonce || nonce.length < 8) {
        throw new Error('Error during nonce creation.');
    }
    return nonce;
};
exports.generateNonce = generateNonce;
/**
 * This method matches the given date string against the ISO-8601 regex and also
 * performs checks if it's a valid date.
 * @param inputDate any string to be validated against ISO-8601
 * @returns boolean indicating if the providade date is valid and conformant to ISO-8601
 */
const isValidISO8601Date = (inputDate) => {
    /* Split groups and make sure inputDate is in ISO8601 format */
    const inputMatch = ISO8601.exec(inputDate);
    /* if inputMatch is null the date is not ISO-8601 */
    if (!inputDate) {
        return false;
    }
    /* Creates a date object with input date to parse for invalid days e.g. Feb, 30 -> Mar, 01 */
    const inputDateParsed = new Date(inputMatch.groups.date).toISOString();
    /* Get groups from new parsed date to compare with the original input */
    const parsedInputMatch = ISO8601.exec(inputDateParsed);
    /* Compare remaining fields */
    return inputMatch.groups.date === parsedInputMatch.groups.date;
};
exports.isValidISO8601Date = isValidISO8601Date;
const checkInvalidKeys = (obj, keys) => {
    const invalidKeys = [];
    Object.keys(obj).forEach((key) => {
        if (!keys.includes(key)) {
            invalidKeys.push(key);
        }
    });
    return invalidKeys;
};
exports.checkInvalidKeys = checkInvalidKeys;
/**
 * This method is supposed to check if an address is conforming to EIP-55.
 * @param address Address to be checked if conforms with EIP-55.
 * @returns Either the return is or not in the EIP-55 format.
 */
const isEIP55Address = (address) => {
    if (address.length != 42) {
        return false;
    }
    const lowerAddress = `${address}`.toLowerCase().replace('0x', '');
    var hash = (0, utils_1.bytesToHex)((0, sha3_1.keccak_256)(lowerAddress));
    var ret = '0x';
    for (var i = 0; i < lowerAddress.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += lowerAddress[i].toUpperCase();
        }
        else {
            ret += lowerAddress[i];
        }
    }
    return address === ret;
};
exports.isEIP55Address = isEIP55Address;
const parseIntegerNumber = (number) => {
    const parsed = parseInt(number);
    // TODO: Fix this
    // if (parsed === NaN) throw new Error('Invalid number.');
    if (parsed === Infinity)
        throw new Error('Invalid number.');
    return parsed;
};
exports.parseIntegerNumber = parseIntegerNumber;
