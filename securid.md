# Support for SecurId RSA MFA

We are able to use SecurId RSA server over PAP protocol as backend for MFA.
Anyway implementation of this functionality required several changes to stock CAS.
I would like to discuss whether there is possibility to accept them upstream.

## Changes in JRADIUS

JRadius doesn't support AccessChalemge response from PAP protocol, instead of that it tries to repeat indefinitely 
AccessRequest, which ends with Access-Reject from RSA server (after roughly 30 seconds and 80000 requests).

Solution we used is to not use authenticate function from JRadius and instead to handle flow explicitly.
In that case we can distinguish Access-Challenge response.

The drawback is that this implementation could break existing implementations, therefore we would suggest to
define custom protocol - say `RSA_SECURID_PAP` and use this special logic only in this case.

This change required also change in processing results from radius authentication.

## Changes in Radius MFA

Actual radius-mfa implementation is not able to report to user any errors. In case of error the flow is returned
to initial state without indication of problem.

To achieve that we had to change webflow and handle TokenChangeException with proper event. 

Even better would be to handle both credential in single screen, but that is bigger change.
