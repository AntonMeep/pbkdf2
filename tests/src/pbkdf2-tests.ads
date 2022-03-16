with AUnit.Test_Fixtures;
with AUnit.Test_Suites;

package PBKDF2.Tests is
   function Suite return AUnit.Test_Suites.Access_Test_Suite;
private
   type Fixture is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure PBKDF2_HMAC_SHA1_Test (Object : in out Fixture);
   procedure PBKDF2_HMAC_SHA256_Test (Object : in out Fixture);
   procedure PBKDF2_HMAC_SHA512_Test (Object : in out Fixture);
end PBKDF2.Tests;
