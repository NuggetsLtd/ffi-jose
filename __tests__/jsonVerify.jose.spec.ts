import { jsonVerify, JWK } from "../src";
import jwks from './jwks.json';

describe("jose", () => {

  describe("jsonVerify", () => {

    describe("should verify signed payload correctly", () => {

      describe('where format is "flattened"', () => {

        describe("where alg type is `ECDSA`", () => {
  
          it("and `alg` = 'Es256'", async () => {
            const jws = {
              protected: 'eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ',
              header: { kid: 'did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1' },
              payload: 'eyJoZWxsbyI6InRoZXJlIn0',
              signature: 'zyb65VQjoc0gO9Lp9pt03kzvco0jrWxYqk04SWgnMJYbWU2ngyWuEXZQiOQw64R76GC4ESGgYFPsOJ6aNRQPyQ'
            }
  
            // @ts-ignore
            const jwk: JWK = jwks[0].public;
  
            const verified = await jsonVerify(jws, jwk);
  
            expect(verified).toEqual({"hello":"there"})
          });
  
        });

      });

      describe('where format is "general"', () => {

        describe("where alg type is `ECDSA`", () => {
  
          it("and `alg` = 'Es256'", async () => {
            const jws =  {
              signatures: [
                {
                  protected: 'eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ',
                  header: { kid: 'did:nuggets:sZziFvdXw8siMvg1P4YS91gG4Lc#key-p256-1' },
                  signature: 'Ko_i6ReJHMy-CIH1mi_lOQ40nz7bJS9XsD3RtbZjwag6MR9ki0ih3JxB1euvedgPrnuSvQLmSAEnDPe3ExGysg'
                },
                {
                  protected: 'eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ',
                  header: { kid: 'did:nuggets:qy8tyYBwveRXKDL2jjYTZENBDi3#key-p256-1' },
                  signature: 'HTuPXW9oUmsGcHhDfFcZJCiItv-Y-40C5bbYO-4orLTs49LqJcrOq67w2DMmQM-McCb_qqHGXiTQPZLAultb8Q'
                }
              ],
              payload: 'eyJoZWxsbyI6InRoZXJlIn0'
            }
  
            // @ts-ignore
            const jwk: JWK = jwks[0].public;
  
            const verified = await jsonVerify(jws, jwk);
  
            expect(verified).toEqual({"hello":"there"})
          });
  
        });

      });
      
    });

  });

});
