# Command line authentication for Go

Authn supports Firebase's auth flow and any supporting PKCE auth flow (tested with Okta).

### Firebase
Firebase auth flow should be used only in development as the unencrypted HTTP redirect server can be intercepted on your local network. Reworking of the library to support a cloud redirect is possible but currently not implemented.

### PKCE flow
PKCE flow does not face the same deficiencies as the Firebase flow. PKCE auth providers use a back channel which allows the code exchange to be secured even though the redirect server is unencrypted. While an attacker would see the redirect, they would not know the code exchange secret which is used to finalized the flow.
Minor adjustments can be made to the library to support third party identity providers.
> PKCE flow was developed using Okta with Okta iself, Google and Github acting as identity providers.