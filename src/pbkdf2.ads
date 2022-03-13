with Ada.Streams; use Ada.Streams;

with GNAT.SHA1;
with GNAT.SHA256;
with GNAT.SHA512;

package PBKDF2 is
   function PBKDF2_HMAC_SHA1
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA1.Hash_Length)
      return Stream_Element_Array;
   function PBKDF2_HMAC_SHA256
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA256.Hash_Length)
      return Stream_Element_Array;
   function PBKDF2_HMAC_SHA512
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA512.Hash_Length)
      return Stream_Element_Array;
end PBKDF2;
