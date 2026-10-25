// Vulnerable catastrophic backtracking regular expression (ReDoS) with nested quantifiers
const REGEX_UNVALIDATED = /^([a-zA-Z0-9]+)+$/;

function validateAlphanumeric(inputString) {
    return REGEX_UNVALIDATED.test(inputString);
}
module.exports = { validateAlphanumeric };
