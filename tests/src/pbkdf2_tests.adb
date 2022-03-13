pragma Ada_2020;

with Ada.Text_IO; use Ada.Text_IO;
with PBKDF2; use PBKDF2;

procedure PBKDF2_Tests is
begin
   Put_Line(PBKDF2_HMAC_SHA1("password", "salt", 1)'Image);
   Put_Line(PBKDF2_HMAC_SHA1("password", "salt", 4096)'Image);
   Put_Line(PBKDF2_HMAC_SHA1("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25)'Image);
end PBKDF2_Tests;
