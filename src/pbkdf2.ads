with Ada.Streams; use Ada.Streams;

with GNAT.SHA1;
with GNAT.SHA256;
with GNAT.SHA512;

package PBKDF2 is
   --  @summary
   --  PBKDF2 algorithm implemented in Ada

   function PBKDF2_HMAC_SHA1
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA1.Hash_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA1 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output

   function PBKDF2_HMAC_SHA256
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA256.Hash_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA256 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output

   function PBKDF2_HMAC_SHA512
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := GNAT.SHA512.Hash_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA512 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output

end PBKDF2;
