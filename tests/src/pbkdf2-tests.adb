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
           (Name & "PBKDF2_HMAC_SHA_1()", PBKDF2_HMAC_SHA_1_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "PBKDF2_HMAC_SHA_256()", PBKDF2_HMAC_SHA_256_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "PBKDF2_HMAC_SHA_512()", PBKDF2_HMAC_SHA_512_Test'Access));

      return Test_Suite'Access;
   end Suite;

   procedure PBKDF2_HMAC_SHA_1_Test (Object : in out Fixture) is
   begin
      Assert
        (PBKDF2_HMAC_SHA_1
           ("password", "salt", Iterations => 1, Derived_Key_Length => 20) =
         (16#0c#, 16#60#, 16#c8#, 16#0f#, 16#96#, 16#1f#, 16#0e#, 16#71#,
          16#f3#, 16#a9#, 16#b5#, 16#24#, 16#af#, 16#60#, 16#12#, 16#06#,
          16#2f#, 16#e0#, 16#37#, 16#a6#),
         "RFC6070-1");
      Assert
        (PBKDF2_HMAC_SHA_1
           ("password", "salt", Iterations => 2, Derived_Key_Length => 20) =
         (16#ea#, 16#6c#, 16#01#, 16#4d#, 16#c7#, 16#2d#, 16#6f#, 16#8c#,
          16#cd#, 16#1e#, 16#d9#, 16#2a#, 16#ce#, 16#1d#, 16#41#, 16#f0#,
          16#d8#, 16#de#, 16#89#, 16#57#),
         "RFC6070-2");
      Assert
        (PBKDF2_HMAC_SHA_1
           ("password", "salt", Iterations => 4_096,
            Derived_Key_Length             => 20) =
         (16#4b#, 16#00#, 16#79#, 16#01#, 16#b7#, 16#65#, 16#48#, 16#9a#,
          16#be#, 16#ad#, 16#49#, 16#d9#, 16#26#, 16#f7#, 16#21#, 16#d0#,
          16#65#, 16#a4#, 16#29#, 16#c1#),
         "RFC6070-3");
      Assert
        (PBKDF2_HMAC_SHA_1
           ("password", "salt", Iterations => 16_777_216,
            Derived_Key_Length             => 20) =
         (16#ee#, 16#fe#, 16#3d#, 16#61#, 16#cd#, 16#4d#, 16#a4#, 16#e4#,
          16#e9#, 16#94#, 16#5b#, 16#3d#, 16#6b#, 16#a2#, 16#15#, 16#8c#,
          16#26#, 16#34#, 16#e9#, 16#84#),
         "RFC6070-4");
      Assert
        (PBKDF2_HMAC_SHA_1
           ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            Iterations => 4_096, Derived_Key_Length => 25) =
         (16#3d#, 16#2e#, 16#ec#, 16#4f#, 16#e4#, 16#1c#, 16#84#, 16#9b#,
          16#80#, 16#c8#, 16#d8#, 16#36#, 16#62#, 16#c0#, 16#e4#, 16#4a#,
          16#8b#, 16#29#, 16#1a#, 16#96#, 16#4c#, 16#f2#, 16#f0#, 16#70#,
          16#38#),
         "RFC6070-5");
      Assert
        (PBKDF2_HMAC_SHA_1
           ("pass" & NUL & "word", "sa" & NUL & "lt", Iterations => 4_096,
            Derived_Key_Length                                   => 16) =
         (16#56#, 16#fa#, 16#6a#, 16#a7#, 16#55#, 16#48#, 16#09#, 16#9d#,
          16#cc#, 16#37#, 16#d7#, 16#f0#, 16#34#, 16#25#, 16#e0#, 16#c3#),
         "RFC6070-6");
   end PBKDF2_HMAC_SHA_1_Test;

   procedure PBKDF2_HMAC_SHA_256_Test (Object : in out Fixture) is
   begin
      Assert
        (PBKDF2_HMAC_SHA_256
           ("passwd", "salt", Iterations => 1, Derived_Key_Length => 64) =
         (16#55#, 16#ac#, 16#04#, 16#6e#, 16#56#, 16#e3#, 16#08#, 16#9f#,
          16#ec#, 16#16#, 16#91#, 16#c2#, 16#25#, 16#44#, 16#b6#, 16#05#,
          16#f9#, 16#41#, 16#85#, 16#21#, 16#6d#, 16#de#, 16#04#, 16#65#,
          16#e6#, 16#8b#, 16#9d#, 16#57#, 16#c2#, 16#0d#, 16#ac#, 16#bc#,
          16#49#, 16#ca#, 16#9c#, 16#cc#, 16#f1#, 16#79#, 16#b6#, 16#45#,
          16#99#, 16#16#, 16#64#, 16#b3#, 16#9d#, 16#77#, 16#ef#, 16#31#,
          16#7c#, 16#71#, 16#b8#, 16#45#, 16#b1#, 16#e3#, 16#0b#, 16#d5#,
          16#09#, 16#11#, 16#20#, 16#41#, 16#d3#, 16#a1#, 16#97#, 16#83#),
         "Test 1");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("Password", "NaCl", Iterations => 80_000,
            Derived_Key_Length             => 64) =
         (16#4d#, 16#dc#, 16#d8#, 16#f6#, 16#0b#, 16#98#, 16#be#, 16#21#,
          16#83#, 16#0c#, 16#ee#, 16#5e#, 16#f2#, 16#27#, 16#01#, 16#f9#,
          16#64#, 16#1a#, 16#44#, 16#18#, 16#d0#, 16#4c#, 16#04#, 16#14#,
          16#ae#, 16#ff#, 16#08#, 16#87#, 16#6b#, 16#34#, 16#ab#, 16#56#,
          16#a1#, 16#d4#, 16#25#, 16#a1#, 16#22#, 16#58#, 16#33#, 16#54#,
          16#9a#, 16#db#, 16#84#, 16#1b#, 16#51#, 16#c9#, 16#b3#, 16#17#,
          16#6a#, 16#27#, 16#2b#, 16#de#, 16#bb#, 16#a1#, 16#d0#, 16#78#,
          16#47#, 16#8f#, 16#62#, 16#b3#, 16#97#, 16#f3#, 16#3c#, 16#8d#),
         "Test 2");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("password", "salt", Iterations => 1, Derived_Key_Length => 32) =
         (16#12#, 16#0f#, 16#b6#, 16#cf#, 16#fc#, 16#f8#, 16#b3#, 16#2c#,
          16#43#, 16#e7#, 16#22#, 16#52#, 16#56#, 16#c4#, 16#f8#, 16#37#,
          16#a8#, 16#65#, 16#48#, 16#c9#, 16#2c#, 16#cc#, 16#35#, 16#48#,
          16#08#, 16#05#, 16#98#, 16#7c#, 16#b7#, 16#0b#, 16#e1#, 16#7b#),
         "Test 3");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("password", "salt", Iterations => 2, Derived_Key_Length => 32) =
         (16#ae#, 16#4d#, 16#0c#, 16#95#, 16#af#, 16#6b#, 16#46#, 16#d3#,
          16#2d#, 16#0a#, 16#df#, 16#f9#, 16#28#, 16#f0#, 16#6d#, 16#d0#,
          16#2a#, 16#30#, 16#3f#, 16#8e#, 16#f3#, 16#c2#, 16#51#, 16#df#,
          16#d6#, 16#e2#, 16#d8#, 16#5a#, 16#95#, 16#47#, 16#4c#, 16#43#),
         "Test 4");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("password", "salt", Iterations => 4_096,
            Derived_Key_Length             => 32) =
         (16#c5#, 16#e4#, 16#78#, 16#d5#, 16#92#, 16#88#, 16#c8#, 16#41#,
          16#aa#, 16#53#, 16#0d#, 16#b6#, 16#84#, 16#5c#, 16#4c#, 16#8d#,
          16#96#, 16#28#, 16#93#, 16#a0#, 16#01#, 16#ce#, 16#4e#, 16#11#,
          16#a4#, 16#96#, 16#38#, 16#73#, 16#aa#, 16#98#, 16#13#, 16#4a#),
         "Test 5");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            Iterations => 4_096, Derived_Key_Length => 40) =
         (16#34#, 16#8c#, 16#89#, 16#db#, 16#cb#, 16#d3#, 16#2b#, 16#2f#,
          16#32#, 16#d8#, 16#14#, 16#b8#, 16#11#, 16#6e#, 16#84#, 16#cf#,
          16#2b#, 16#17#, 16#34#, 16#7e#, 16#bc#, 16#18#, 16#00#, 16#18#,
          16#1c#, 16#4e#, 16#2a#, 16#1f#, 16#b8#, 16#dd#, 16#53#, 16#e1#,
          16#c6#, 16#35#, 16#51#, 16#8c#, 16#7d#, 16#ac#, 16#47#, 16#e9#),
         "Test 6");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("", "salt", Iterations => 1_024, Derived_Key_Length => 32) =
         (16#9e#, 16#83#, 16#f2#, 16#79#, 16#c0#, 16#40#, 16#f2#, 16#a1#,
          16#1a#, 16#a4#, 16#a0#, 16#2b#, 16#24#, 16#c4#, 16#18#, 16#f2#,
          16#d3#, 16#cb#, 16#39#, 16#56#, 16#0c#, 16#96#, 16#27#, 16#fa#,
          16#4f#, 16#47#, 16#e3#, 16#bc#, 16#c2#, 16#89#, 16#7c#, 16#3d#),
         "Test 7");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("password", "", Iterations => 1_024, Derived_Key_Length => 32) =
         (16#ea#, 16#58#, 16#08#, 16#41#, 16#1e#, 16#b0#, 16#c7#, 16#e8#,
          16#30#, 16#de#, 16#ab#, 16#55#, 16#09#, 16#6c#, 16#ee#, 16#58#,
          16#27#, 16#61#, 16#e2#, 16#2a#, 16#9b#, 16#c0#, 16#34#, 16#e3#,
          16#ec#, 16#e9#, 16#25#, 16#22#, 16#5b#, 16#07#, 16#bf#, 16#46#),
         "Test 8");
      Assert
        (PBKDF2_HMAC_SHA_256
           ("pass" & NUL & "word", "sa" & NUL & "lt", Iterations => 4_096,
            Derived_Key_Length                                   => 16) =
         (16#89#, 16#b6#, 16#9d#, 16#05#, 16#16#, 16#f8#, 16#29#, 16#89#,
          16#3c#, 16#69#, 16#62#, 16#26#, 16#65#, 16#0a#, 16#86#, 16#87#),
         "Test 9");
   end PBKDF2_HMAC_SHA_256_Test;

   procedure PBKDF2_HMAC_SHA_512_Test (Object : in out Fixture) is
   begin
      Assert
        (PBKDF2_HMAC_SHA_512
           ("password", "salt", Iterations => 1, Derived_Key_Length => 32) =
         (16#86#, 16#7f#, 16#70#, 16#cf#, 16#1a#, 16#de#, 16#02#, 16#cf#,
          16#f3#, 16#75#, 16#25#, 16#99#, 16#a3#, 16#a5#, 16#3d#, 16#c4#,
          16#af#, 16#34#, 16#c7#, 16#a6#, 16#69#, 16#81#, 16#5a#, 16#e5#,
          16#d5#, 16#13#, 16#55#, 16#4e#, 16#1c#, 16#8c#, 16#f2#, 16#52#),
         "Test 1");
      Assert
        (PBKDF2_HMAC_SHA_512
           ("password", "salt", Iterations => 2, Derived_Key_Length => 32) =
         (16#e1#, 16#d9#, 16#c1#, 16#6a#, 16#a6#, 16#81#, 16#70#, 16#8a#,
          16#45#, 16#f5#, 16#c7#, 16#c4#, 16#e2#, 16#15#, 16#ce#, 16#b6#,
          16#6e#, 16#01#, 16#1a#, 16#2e#, 16#9f#, 16#00#, 16#40#, 16#71#,
          16#3f#, 16#18#, 16#ae#, 16#fd#, 16#b8#, 16#66#, 16#d5#, 16#3c#),
         "Test 2");
      Assert
        (PBKDF2_HMAC_SHA_512
           ("password", "salt", Iterations => 4_096,
            Derived_Key_Length             => 32) =
         (16#d1#, 16#97#, 16#b1#, 16#b3#, 16#3d#, 16#b0#, 16#14#, 16#3e#,
          16#01#, 16#8b#, 16#12#, 16#f3#, 16#d1#, 16#d1#, 16#47#, 16#9e#,
          16#6c#, 16#de#, 16#bd#, 16#cc#, 16#97#, 16#c5#, 16#c0#, 16#f8#,
          16#7f#, 16#69#, 16#02#, 16#e0#, 16#72#, 16#f4#, 16#57#, 16#b5#),
         "Test 3");
      Assert
        (PBKDF2_HMAC_SHA_512
           ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            Iterations => 1, Derived_Key_Length => 72) =
         (16#6e#, 16#23#, 16#f2#, 16#76#, 16#38#, 16#08#, 16#4b#, 16#0f#,
          16#7e#, 16#a1#, 16#73#, 16#4e#, 16#0d#, 16#98#, 16#41#, 16#f5#,
          16#5d#, 16#d2#, 16#9e#, 16#a6#, 16#0a#, 16#83#, 16#44#, 16#66#,
          16#f3#, 16#39#, 16#6b#, 16#ac#, 16#80#, 16#1f#, 16#ac#, 16#1e#,
          16#eb#, 16#63#, 16#80#, 16#2f#, 16#03#, 16#a0#, 16#b4#, 16#ac#,
          16#d7#, 16#60#, 16#3e#, 16#36#, 16#99#, 16#c8#, 16#b7#, 16#44#,
          16#37#, 16#be#, 16#83#, 16#ff#, 16#01#, 16#ad#, 16#7f#, 16#55#,
          16#da#, 16#c1#, 16#ef#, 16#60#, 16#f4#, 16#d5#, 16#64#, 16#80#,
          16#c3#, 16#5e#, 16#e6#, 16#8f#, 16#d5#, 16#2c#, 16#69#, 16#36#),
         "Test 4");
   end PBKDF2_HMAC_SHA_512_Test;
end PBKDF2.Tests;
