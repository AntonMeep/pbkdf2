pragma Ada_2012;

with Ada.Characters.Latin_1; use Ada.Characters.Latin_1;

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
      Assert
        (PBKDF2_HMAC_SHA1
           ("password", "salt", Iterations => 1, Derived_Key_Length => 20) =
         (16#0c#, 16#60#, 16#c8#, 16#0f#, 16#96#, 16#1f#, 16#0e#, 16#71#,
          16#f3#, 16#a9#, 16#b5#, 16#24#, 16#af#, 16#60#, 16#12#, 16#06#,
          16#2f#, 16#e0#, 16#37#, 16#a6#),
         "RFC6070-1");
      Assert
        (PBKDF2_HMAC_SHA1
           ("password", "salt", Iterations => 2, Derived_Key_Length => 20) =
         (16#ea#, 16#6c#, 16#01#, 16#4d#, 16#c7#, 16#2d#, 16#6f#, 16#8c#,
          16#cd#, 16#1e#, 16#d9#, 16#2a#, 16#ce#, 16#1d#, 16#41#, 16#f0#,
          16#d8#, 16#de#, 16#89#, 16#57#),
         "RFC6070-2");
      Assert
        (PBKDF2_HMAC_SHA1
           ("password", "salt", Iterations => 4_096,
            Derived_Key_Length             => 20) =
         (16#4b#, 16#00#, 16#79#, 16#01#, 16#b7#, 16#65#, 16#48#, 16#9a#,
          16#be#, 16#ad#, 16#49#, 16#d9#, 16#26#, 16#f7#, 16#21#, 16#d0#,
          16#65#, 16#a4#, 16#29#, 16#c1#),
         "RFC6070-3");
      Assert
        (PBKDF2_HMAC_SHA1
           ("password", "salt", Iterations => 16_777_216,
            Derived_Key_Length             => 20) =
         (16#ee#, 16#fe#, 16#3d#, 16#61#, 16#cd#, 16#4d#, 16#a4#, 16#e4#,
          16#e9#, 16#94#, 16#5b#, 16#3d#, 16#6b#, 16#a2#, 16#15#, 16#8c#,
          16#26#, 16#34#, 16#e9#, 16#84#),
         "RFC6070-4");
      Assert
        (PBKDF2_HMAC_SHA1
           ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            Iterations => 4_096, Derived_Key_Length => 25) =
         (16#3d#, 16#2e#, 16#ec#, 16#4f#, 16#e4#, 16#1c#, 16#84#, 16#9b#,
          16#80#, 16#c8#, 16#d8#, 16#36#, 16#62#, 16#c0#, 16#e4#, 16#4a#,
          16#8b#, 16#29#, 16#1a#, 16#96#, 16#4c#, 16#f2#, 16#f0#, 16#70#,
          16#38#),
         "RFC6070-5");
      Assert
        (PBKDF2_HMAC_SHA1
           ("pass" & NUL & "word", "sa" & NUL & "lt", Iterations => 4_096,
            Derived_Key_Length                                   => 16) =
         (16#56#, 16#fa#, 16#6a#, 16#a7#, 16#55#, 16#48#, 16#09#, 16#9d#,
          16#cc#, 16#37#, 16#d7#, 16#f0#, 16#34#, 16#25#, 16#e0#, 16#c3#),
         "RFC6070-6");
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
