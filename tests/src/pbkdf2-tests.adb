pragma Ada_2012;

with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Caller;

package body PBKDF2.Tests is
   package Caller is new AUnit.Test_Caller (Fixture);

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Name : constant String := "[PBKDF2] ";
   begin
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "PBKDF2_HMAC_SHA1()", PBKDF2_HMAC_SHA1_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "PBKDF2_HMAC_SHA256()", PBKDF2_HMAC_SHA256_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "PBKDF2_HMAC_SHA512()", PBKDF2_HMAC_SHA512_Test'Access));

      return Test_Suite'Access;
   end Suite;

   procedure PBKDF2_HMAC_SHA1_Test (Object : in out Fixture) is
   begin
      Assert (False, "not implemented");
   end PBKDF2_HMAC_SHA1_Test;

   procedure PBKDF2_HMAC_SHA256_Test (Object : in out Fixture) is
   begin
      Assert (False, "not implemented");
   end PBKDF2_HMAC_SHA256_Test;

   procedure PBKDF2_HMAC_SHA512_Test (Object : in out Fixture) is
   begin
      Assert (False, "not implemented");
   end PBKDF2_HMAC_SHA512_Test;
end PBKDF2.Tests;
