const usersByEmail = new Map();
const sessionsByHash = new Map();

function clearStores() {
  usersByEmail.clear();
  sessionsByHash.clear();
}

module.exports = { usersByEmail, sessionsByHash, clearStores };
