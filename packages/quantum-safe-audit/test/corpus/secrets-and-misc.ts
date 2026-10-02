// Embedded key material and other source-level findings.
// expect-next: QSJ060
export const leaked = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK
-----END RSA PRIVATE KEY-----`;

export const alsoLeaked = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----'; // expect: QSJ060

// A PEM *header* alone (for example in a regex or a check) is not a leaked key.
export const isPem = (s: string) => s.startsWith('-----BEGIN PRIVATE KEY-----');
export const placeholder = '-----BEGIN PRIVATE KEY-----';
export const publicOk = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
-----END PUBLIC KEY-----`;

// Suppressions
const ignoredSameLine = require('node:crypto').createHash('md5'); // qs-audit-ignore QSJ031 legacy ETag compatibility
// qs-audit-ignore QSJ030 interop with a legacy server
const ignoredNextLine = require('node:crypto').createHash('sha1');
const stillFlagged = require('node:crypto').createHash('md5'); // expect: QSJ031
