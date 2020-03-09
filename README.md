# android-id-attestation

I was trying to create a demo that showcase Android ID attestsion (https://source.android.com/security/keystore/attestation). But so far no success yet.  Nontheless, the learning is interesting enough so I like to share.

Here is what it does

- generate a key pair with challenge phrase in keystore
- fetch the key pair and its certificate chain
- display cert[0] extension data with bouncy castle

The last step borrows code heavily from google's example, https://github.com/google/android-key-attestation/tree/master/server

Tested on a several phones (nexus 5x, pixel 4, oneplus 7).  They all show IDs are not present in the certificate.  It is not clear how to force them to show up (or they are just not availabe at the first place?)  This file (https://android.googlesource.com/platform/frameworks/base/+/master/keystore/java/android/security/keystore/AttestationUtils.java) offers some clue, but not sure how to do this from app level.

Also it is not clear to me how to separate key generation step from key attestation step.  Right now they are molded together. 

Would love to hear from you!

References:
- key generation and retrival is inspired by this kotlin demo, https://github.com/nodh/android-key-attestation-demo
