with Ada.Streams; use Ada.Streams;

with HMAC;
with SHA1;
with SHA2;

package PBKDF2 with Pure, Preelaborate is
   --  @summary
   --  PBKDF2 algorithm implemented in Ada

   function PBKDF2_HMAC_SHA_1
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA1.Digest_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA_1 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output

   function PBKDF2_HMAC_SHA_256
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_256.Digest_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA256 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output

   function PBKDF2_HMAC_SHA_512
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_512.Digest_Length)
      return Stream_Element_Array;
   --  Computes PBKDF2_HMAC_SHA_512 of Password, Salt with specified number of
   --  Iterations.
   --  @param Password Input password
   --  @param Salt Input salt
   --  @param Iterations number of iterations
   --  @param Derived_Key_Length length, in bytes, of the output result array
   --  @returns Derived_Key_Length bytes of PBKDF2 output
end PBKDF2;
