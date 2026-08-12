const lodash = require("lodash");

if (lodash.camelCase("clean verification") !== "cleanVerification") {
  process.exit(1);
}
