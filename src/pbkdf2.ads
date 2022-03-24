with Ada.Streams; use Ada.Streams;

with PBKDF2_Generic;

with HMAC; use HMAC;
with SHA1;
with SHA2;

package PBKDF2 with
   Pure,
   Preelaborate
is
   package PBKDF2_HMAC_SHA_1_Package is new PBKDF2_Generic
     (Element         => Stream_Element, Index => Stream_Element_Offset,
      Element_Array => Stream_Element_Array, Hash_Length => SHA1.Digest_Length,
      Hash_Context    => HMAC_SHA_1.Context,
      Hash_Initialize => HMAC_SHA_1.Initialize,
      Hash_Update => HMAC_SHA_1.Update, Hash_Finalize => HMAC_SHA_1.Finalize);

   function PBKDF2_HMAC_SHA_1
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA1.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_1_Package.PBKDF2;

   function PBKDF2_HMAC_SHA_1
     (Password           : Stream_Element_Array; Salt : Stream_Element_Array;
      Iterations         : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA1.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_1_Package.PBKDF2;

   package PBKDF2_HMAC_SHA_256_Package is new PBKDF2_Generic
     (Element         => Stream_Element, Index => Stream_Element_Offset,
      Element_Array   => Stream_Element_Array,
      Hash_Length     => SHA2.SHA_256.Digest_Length,
      Hash_Context    => HMAC_SHA_256.Context,
      Hash_Initialize => HMAC_SHA_256.Initialize,
      Hash_Update     => HMAC_SHA_256.Update,
      Hash_Finalize   => HMAC_SHA_256.Finalize);

   function PBKDF2_HMAC_SHA_256
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_256.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_256_Package.PBKDF2;

   function PBKDF2_HMAC_SHA_256
     (Password           : Stream_Element_Array; Salt : Stream_Element_Array;
      Iterations         : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_256.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_256_Package.PBKDF2;

   package PBKDF2_HMAC_SHA_512_Package is new PBKDF2_Generic
     (Element         => Stream_Element, Index => Stream_Element_Offset,
      Element_Array   => Stream_Element_Array,
      Hash_Length     => SHA2.SHA_512.Digest_Length,
      Hash_Context    => HMAC_SHA_512.Context,
      Hash_Initialize => HMAC_SHA_512.Initialize,
      Hash_Update     => HMAC_SHA_512.Update,
      Hash_Finalize   => HMAC_SHA_512.Finalize);

   function PBKDF2_HMAC_SHA_512
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_512.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_512_Package.PBKDF2;

   function PBKDF2_HMAC_SHA_512
     (Password           : Stream_Element_Array; Salt : Stream_Element_Array;
      Iterations         : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_512.Digest_Length)
      return Stream_Element_Array renames
     PBKDF2_HMAC_SHA_512_Package.PBKDF2;
end PBKDF2;
