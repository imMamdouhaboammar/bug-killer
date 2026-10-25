// Safe deterministic linear regex without overlapping nested repetitions
const REGEX_SAFE = /^[a-zA-Z0-9]+$/;

function validateAlphanumericSafe(inputString) {
    return REGEX_SAFE.test(inputString);
}
module.exports = { validateAlphanumericSafe };
