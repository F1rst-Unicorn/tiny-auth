CID = client identifying information
This includes
* user name
* tokens

This excludes
* client IDs
* scope names

CID is logged at DEBUG at most. Passwords or password attempts are never logged.

business layer entry point logs client and user name

To easily keep the log clean of CID, all CID fields have to be contained in
spans named `cid`.