A simple e-vote system, which includes three phases:

1) Authentication. A student enters his/her ID, a short random code is sent to the corresponding email connected to that ID. The student enters the code, the system verifies and gives permission to proceed.

2) Toekn generation. Toekn is generated and signed via RSA blind signature.

3) E-vote. The student enters the system providing the signed token and its hash. The system verifies the signature, if true, gives permission to vote. The votes are committed, collected and computed in the end via Paillier system.

